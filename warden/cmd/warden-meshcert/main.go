// Command warden-meshcert is a LOCAL bootstrap tool that provisions a mesh mTLS
// certificate (gateway/worker/warden identity) for dev environments.
//
// It talks to the mesh CA directly through the database + master key rather than
// over the network, deliberately avoiding the chicken-and-egg of needing a mesh
// cert to reach warden's mesh listener. It generates the private key locally
// (the key never leaves this machine), signs a CSR against the active mesh CA,
// and writes cert.pem, key.pem, and ca-bundle.pem into the output directory.
//
// Usage:
//
//	DATABASE_URL=... VAULT_MASTER_KEY=... \
//	  warden-meshcert -spiffe spiffe://jumpgate/gateway/gw -out ./certs
//
// The mesh CA must already be initialized (VaultService.InitMeshCA).
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/pg"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// meshCertTTL matches the server-side IssueMeshCert validity window.
const meshCertTTL = 90 * 24 * time.Hour

func main() {
	spiffeID := flag.String("spiffe", "", "SPIFFE id to mint (e.g. spiffe://jumpgate/gateway/gw)")
	outDir := flag.String("out", ".", "output directory for cert.pem, key.pem, ca-bundle.pem")
	flag.Parse()

	if *spiffeID == "" {
		log.Fatal("-spiffe is required (e.g. spiffe://jumpgate/gateway/gw)")
	}
	u, err := url.Parse(*spiffeID)
	if err != nil {
		log.Fatalf("parse -spiffe: %v", err)
	}
	if _, err := mesh.ParseIdentity(u); err != nil {
		log.Fatalf("invalid -spiffe: %v", err)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	key, err := secrets.MasterKeyFromConfig(os.Getenv("VAULT_MASTER_KEY"))
	if err != nil {
		log.Fatalf("VAULT_MASTER_KEY: %v", err)
	}
	sealer, err := secrets.NewSealer(key)
	if err != nil {
		log.Fatalf("sealer: %v", err)
	}

	ctx := context.Background()
	pool, err := pg.NewPool(ctx, dsn)
	if err != nil {
		log.Fatalf("db pool: %v", err)
	}
	defer pool.Close()

	row, err := gen.New(pool).GetActiveCA(ctx, "mesh")
	if errors.Is(err, pgx.ErrNoRows) {
		log.Fatal("mesh CA not initialized: run VaultService.InitMeshCA first")
	}
	if err != nil {
		log.Fatalf("load mesh CA: %v", err)
	}
	caKeyDER, err := sealer.Open(row.Sealed)
	if err != nil {
		log.Fatalf("unseal mesh CA key: %v", err)
	}
	mca, err := ca.LoadMeshCA(caKeyDER, []byte(row.PublicMaterial))
	if err != nil {
		log.Fatalf("parse mesh CA: %v", err)
	}

	keyDER, csrDER, err := ca.GenerateCSR(*spiffeID)
	if err != nil {
		log.Fatalf("generate CSR: %v", err)
	}
	leafPEM, bundlePEM, err := mca.SignCSR(csrDER, *spiffeID, meshCertTTL)
	if err != nil {
		log.Fatalf("sign CSR: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		log.Fatalf("mkdir %s: %v", *outDir, err)
	}
	write := func(name string, data []byte, perm os.FileMode) {
		// name is a fixed literal below; *outDir is an operator-supplied flag on a
		// local bootstrap tool, so an unconstrained output path is intended.
		path := filepath.Join(*outDir, name)
		if err := os.WriteFile(path, data, perm); err != nil { // #nosec G304,G703 -- operator-controlled output dir
			log.Fatalf("write %s: %v", path, err)
		}
	}
	write("cert.pem", leafPEM, 0o644)
	write("key.pem", keyPEM, 0o600)
	write("ca-bundle.pem", bundlePEM, 0o644)

	log.Printf("wrote mesh cert for %s to %s (cert.pem, key.pem, ca-bundle.pem)", *spiffeID, *outDir)
}
