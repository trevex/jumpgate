// Command warden-bootstrap is a k8s-agnostic, one-shot provisioner that seeds
// jumpgate's crypto material into Postgres and emits the public files that the
// data plane needs at boot. It encapsulates what the full-stack e2e harness does
// inline (SSH CA, session signing key, mesh CA) so the same provisioning can run
// as a Kubernetes init container.
//
// Every step is idempotent: re-running against an already-provisioned database
// is a no-op (existing active material is kept and re-emitted, no duplicates are
// created).
//
// Usage:
//
//	DATABASE_URL=... VAULT_MASTER_KEY=<base64-32-bytes> \
//	  warden-bootstrap --out /work [--skip-mesh-ca] \
//	    [--admin-email a@b.c --admin-password ...]
//
// Emitted into --out:
//
//	ssh-ca.pub   the active SSH CA's authorized_keys public line (0644)
//	mesh-ca.crt  the mesh CA certificate PEM (0644)          [unless --skip-mesh-ca]
//	mesh-ca.key  the mesh CA private key PEM, PKCS#8 (0600)  [unless --skip-mesh-ca]
//
// The mesh CA files are shaped for cert-manager's CA Issuer (tls.crt + tls.key).
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/bootstrap"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/pg"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
)

// config captures the resolved inputs for a single bootstrap run.
type config struct {
	dsn           string
	masterKeyB64  string
	outDir        string
	skipMeshCA    bool
	adminEmail    string
	adminPassword string
}

func main() {
	outDir := flag.String("out", "/work", "output directory for emitted public material")
	skipMeshCA := flag.Bool("skip-mesh-ca", false, "do not generate/emit the mesh CA")
	adminEmail := flag.String("admin-email", "", "bootstrap admin email (fallback env BOOTSTRAP_ADMIN_EMAIL)")
	adminPassword := flag.String("admin-password", "", "bootstrap admin password (fallback env BOOTSTRAP_ADMIN_PASSWORD)")
	flag.Parse()

	cfg := config{
		dsn:           os.Getenv("DATABASE_URL"),
		masterKeyB64:  os.Getenv("VAULT_MASTER_KEY"),
		outDir:        *outDir,
		skipMeshCA:    *skipMeshCA,
		adminEmail:    firstNonEmpty(*adminEmail, os.Getenv("BOOTSTRAP_ADMIN_EMAIL")),
		adminPassword: firstNonEmpty(*adminPassword, os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")),
	}

	if err := run(context.Background(), cfg); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// run performs the full idempotent provisioning sequence against cfg.dsn.
func run(ctx context.Context, cfg config) error {
	if cfg.dsn == "" {
		return errors.New("DATABASE_URL is required")
	}

	// 1. Apply schema migrations (idempotent).
	if err := migrate.Up(cfg.dsn); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// 2. Build the sealer from the master key.
	key, err := secrets.MasterKeyFromConfig(cfg.masterKeyB64)
	if err != nil {
		return fmt.Errorf("VAULT_MASTER_KEY: %w", err)
	}
	sealer, err := secrets.NewSealer(key)
	if err != nil {
		return fmt.Errorf("sealer: %w", err)
	}

	// 3. Open the connection pool.
	pool, err := pg.NewPool(ctx, cfg.dsn)
	if err != nil {
		return fmt.Errorf("db pool: %w", err)
	}
	defer pool.Close()
	q := gen.New(pool)

	if err := os.MkdirAll(cfg.outDir, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", cfg.outDir, err)
	}

	// 4. SSH CA: generate + store only if none is active, then emit its public line.
	if err := provisionSSHCA(ctx, q, sealer, cfg.outDir); err != nil {
		return err
	}

	// 5. Session signing key (idempotent).
	if err := provisionSessionKey(ctx, q, sealer); err != nil {
		return err
	}

	// 6. Mesh CA: generate + emit its cert/key files (unless skipped).
	if !cfg.skipMeshCA {
		if err := provisionMeshCA(ctx, q, sealer, cfg.outDir); err != nil {
			return err
		}
	}

	// 7. Admin user (idempotent; only when both email and password are set).
	if err := bootstrap.EnsureAdmin(ctx, q, cfg.adminEmail, cfg.adminPassword); err != nil {
		return fmt.Errorf("ensure admin: %w", err)
	}

	return nil
}

// provisionSSHCA ensures an active SSH CA exists (generating and sealing one on
// first run) and writes the active CA's authorized_keys public line to
// <out>/ssh-ca.pub.
func provisionSSHCA(ctx context.Context, q *gen.Queries, sealer *secrets.Sealer, outDir string) error {
	_, err := q.GetActiveCA(ctx, "ssh")
	if errors.Is(err, pgx.ErrNoRows) {
		seed, line, gerr := ca.GenerateSSHCA()
		if gerr != nil {
			return fmt.Errorf("generate ssh ca: %w", gerr)
		}
		sealed, serr := sealer.Seal(seed)
		if serr != nil {
			return fmt.Errorf("seal ssh ca: %w", serr)
		}
		if _, cerr := q.CreateCAKey(ctx, gen.CreateCAKeyParams{
			Kind: "ssh", Sealed: sealed, PublicMaterial: line,
		}); cerr != nil {
			return fmt.Errorf("store ssh ca: %w", cerr)
		}
	} else if err != nil {
		return fmt.Errorf("load ssh ca: %w", err)
	}

	// Re-read so we always emit the currently-active material (idempotent across runs).
	row, err := q.GetActiveCA(ctx, "ssh")
	if err != nil {
		return fmt.Errorf("reload ssh ca: %w", err)
	}
	path := filepath.Join(outDir, "ssh-ca.pub")
	if err := os.WriteFile(path, []byte(row.PublicMaterial+"\n"), 0o644); err != nil { //nolint:gosec // public key material is world-readable by design
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// provisionSessionKey initializes the active session signing key if none exists.
// A second run is a no-op (Init would otherwise collide on the unique-active
// index, so we gate on LoadActive first).
func provisionSessionKey(ctx context.Context, q *gen.Queries, sealer *secrets.Sealer) error {
	ks := session.NewKeyStore(q, sealer)
	_, _, err := ks.LoadActive(ctx)
	if errors.Is(err, session.ErrNoActiveKey) {
		if ierr := ks.Init(ctx); ierr != nil {
			return fmt.Errorf("init session key: %w", ierr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load session key: %w", err)
	}
	return nil
}

// provisionMeshCA ensures an active mesh CA exists (generating and sealing one on
// first run) and writes the active CA's cert + key PEM files. The private key is
// stored as PKCS#8 DER; it is PEM-wrapped here as a PRIVATE KEY block for
// cert-manager's CA Issuer (tls.crt + tls.key).
func provisionMeshCA(ctx context.Context, q *gen.Queries, sealer *secrets.Sealer, outDir string) error {
	row, err := q.GetActiveCA(ctx, "mesh")
	if errors.Is(err, pgx.ErrNoRows) {
		keyDER, certPEM, gerr := ca.GenerateMeshCA()
		if gerr != nil {
			return fmt.Errorf("generate mesh ca: %w", gerr)
		}
		sealed, serr := sealer.Seal(keyDER)
		if serr != nil {
			return fmt.Errorf("seal mesh ca: %w", serr)
		}
		if _, cerr := q.CreateCAKey(ctx, gen.CreateCAKeyParams{
			Kind: "mesh", Sealed: sealed, PublicMaterial: string(certPEM),
		}); cerr != nil {
			return fmt.Errorf("store mesh ca: %w", cerr)
		}
		row, err = q.GetActiveCA(ctx, "mesh")
	}
	if err != nil {
		return fmt.Errorf("load mesh ca: %w", err)
	}

	// Unseal the active key so the emitted key.pem always matches the emitted cert
	// (works whether we just generated it or it already existed).
	keyDER, err := sealer.Open(row.Sealed)
	if err != nil {
		return fmt.Errorf("unseal mesh ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	crtPath := filepath.Join(outDir, "mesh-ca.crt")
	if err := os.WriteFile(crtPath, []byte(row.PublicMaterial), 0o644); err != nil { //nolint:gosec // CA certificate is public material
		return fmt.Errorf("write %s: %w", crtPath, err)
	}
	keyPath := filepath.Join(outDir, "mesh-ca.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	return nil
}
