// Package migrations holds Go-based goose migrations for the steps SQL cannot express
// safely — specifically fingerprinting OpenSSH and X.509 material, where a well-formed
// base64 blob that is not a real key or certificate must never be fingerprinted and
// trusted. The SQL migrations live beside this file as embedded *.sql; these Go
// migrations are registered with the goose provider by the parent migrate package and
// run interleaved with the SQL ones strictly in version order.
package migrations

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/ssh"
)

// GoMigrations returns every Go-based migration for goose.WithGoMigrations. Ordering
// against the SQL migrations is by version number, not registration order.
func GoMigrations() []*goose.Migration {
	return []*goose.Migration{legacyPins()}
}

// legacyPins is migration version 11: carry each asset's pinned legacy trust value
// (ssh_asset_config.host_public_key / {postgres,rdp}_asset_config.target_server_ca)
// forward into an approved migration-source trust anchor, so a real upgrade of a DB
// with pinned assets keeps its trust once sessions require a current anchor. It runs
// after 0006 created target_trust_anchors and after 0007/0008/0009 queued the companion
// onboarding probes, and STRICTLY BEFORE the version-12 SQL migration drops the legacy
// columns — so the carry-forward always reads the columns before they are gone. Unpinned
// or unparseable assets get no anchor and stay pending until an operator probes/approves.
//
// The drop lives in a separate SQL migration (0012) rather than here so that the
// schema-only goose CLI used by sqlc codegen (hack/gen-sqlc.sh, which cannot run Go
// migrations) still applies it and generates against the post-drop schema.
func legacyPins() *goose.Migration {
	return goose.NewGoMigration(11,
		&goose.GoFunc{RunTx: legacyPinsUp},
		// Down is a no-op: the carry-forward only inserts idempotent migration-source
		// anchors, which 0007/0008/0009 already declare are left in place on down.
		&goose.GoFunc{RunTx: func(context.Context, *sql.Tx) error { return nil }},
	)
}

func legacyPinsUp(ctx context.Context, tx *sql.Tx) error {
	if err := BackfillSSHTrustAnchors(ctx, tx); err != nil {
		return err
	}
	if err := BackfillPostgresTrustAnchors(ctx, tx); err != nil {
		return err
	}
	return BackfillRDPTrustAnchors(ctx, tx)
}

// BackfillSSHTrustAnchors converts each SSH asset's pinned host_public_key into an
// approved migration-source trust anchor at the asset's current endpoint revision, so
// assets trusted by a pinned key stay verified once sessions require a current anchor.
// An empty or unparseable pin is skipped (never trusted); the asset stays pending until
// an operator probes and approves it. Idempotent via WHERE NOT EXISTS, so re-running
// inserts no duplicate anchor for a pin already migrated at that revision.
func BackfillSSHTrustAnchors(ctx context.Context, tx *sql.Tx) error {
	type pin struct {
		assetID  string
		revision int64
		hostKey  string
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.asset_id::text, a.endpoint_revision, c.host_public_key
		FROM ssh_asset_config c
		JOIN assets a ON a.id = c.asset_id
		WHERE c.host_public_key <> ''`)
	if err != nil {
		return fmt.Errorf("read ssh pins: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var pins []pin
	for rows.Next() {
		var p pin
		if err := rows.Scan(&p.assetID, &p.revision, &p.hostKey); err != nil {
			return fmt.Errorf("scan ssh pin: %w", err)
		}
		pins = append(pins, p)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate ssh pins: %w", err)
	}

	for _, p := range pins {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.hostKey))
		if err != nil {
			// An unparseable pin is never trusted; the asset stays pending until an
			// operator probes and approves it.
			continue
		}
		fingerprint := ssh.FingerprintSHA256(key)
		material := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		// approved_at defaults to now() and approved_by is left NULL because the trust
		// is migration-sourced (an already-pinned key carried forward), not a human
		// approval.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO target_trust_anchors
				(asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source)
			SELECT $1::uuid, $2, 'ssh_host_key', $3, $4, $5, 'migration'
			WHERE NOT EXISTS (
				SELECT 1 FROM target_trust_anchors
				WHERE asset_id = $1::uuid AND endpoint_revision = $2
				  AND sha256_fingerprint = $4 AND source = 'migration' AND revoked_at IS NULL
			)`,
			p.assetID, p.revision, key.Type(), fingerprint, material); err != nil {
			return fmt.Errorf("insert ssh migration anchor for asset %s: %w", p.assetID, err)
		}
	}
	return nil
}

// BackfillPostgresTrustAnchors converts each postgres asset's configured
// target_server_ca PEM into an approved migration-source tls_ca anchor (see
// backfillCATrustAnchors).
func BackfillPostgresTrustAnchors(ctx context.Context, tx *sql.Tx) error {
	return backfillCATrustAnchors(ctx, tx, "postgres_asset_config")
}

// BackfillRDPTrustAnchors converts each rdp asset's configured target_server_ca PEM
// into an approved migration-source tls_ca anchor (see backfillCATrustAnchors).
func BackfillRDPTrustAnchors(ctx context.Context, tx *sql.Tx) error {
	return backfillCATrustAnchors(ctx, tx, "rdp_asset_config")
}

// backfillCATrustAnchors converts each asset's configured target_server_ca PEM in
// configTable into an approved migration-source tls_ca anchor at the asset's current
// endpoint revision, with a required DNS name derived from the normalized target host,
// so assets trusted by a pinned server CA stay verified once sessions require a current
// anchor. The fingerprint is the canonical "SHA256:" + raw-std-base64 over the CA DER,
// matching the worker's FingerprintDER so the anchor compares equal to a session-time
// observed chain. An empty or unparseable CA is skipped (never trusted). Idempotent via
// WHERE NOT EXISTS. configTable is a fixed literal, never user input.
func backfillCATrustAnchors(ctx context.Context, tx *sql.Tx, configTable string) error {
	type conf struct {
		assetID  string
		revision int64
		target   string
		serverCA string
	}
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
		SELECT c.asset_id::text, a.endpoint_revision, c.target_address, c.target_server_ca
		FROM %s c
		JOIN assets a ON a.id = c.asset_id
		WHERE c.target_server_ca <> ''`, configTable))
	if err != nil {
		return fmt.Errorf("read %s CAs: %w", configTable, err)
	}
	defer func() { _ = rows.Close() }()
	var confs []conf
	for rows.Next() {
		var c conf
		if err := rows.Scan(&c.assetID, &c.revision, &c.target, &c.serverCA); err != nil {
			return fmt.Errorf("scan %s CA: %w", configTable, err)
		}
		confs = append(confs, c)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s CAs: %w", configTable, err)
	}

	for _, c := range confs {
		cert := firstCertificate(c.serverCA)
		if cert == nil {
			// An empty or unparseable CA is never trusted; the asset stays pending until
			// an operator probes and approves it.
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		material := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO target_trust_anchors
				(asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source, required_dns_names)
			SELECT $1::uuid, $2, 'tls_ca', $3, $4, $5, 'migration', ARRAY[$6]::text[]
			WHERE NOT EXISTS (
				SELECT 1 FROM target_trust_anchors
				WHERE asset_id = $1::uuid AND endpoint_revision = $2
				  AND sha256_fingerprint = $4 AND source = 'migration' AND revoked_at IS NULL
			)`,
			c.assetID, c.revision, strings.ToLower(cert.PublicKeyAlgorithm.String()), fingerprint, material, normalizeHost(c.target)); err != nil {
			return fmt.Errorf("insert %s migration anchor for asset %s: %w", configTable, c.assetID, err)
		}
	}
	return nil
}

// firstCertificate returns the first parseable CERTIFICATE PEM block in caPEM, or nil
// if none parse. Never fabricates trust: a blob that is not a real certificate yields
// nil so the caller skips it.
func firstCertificate(caPEM string) *x509.Certificate {
	rest := []byte(caPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert
		}
	}
}

// normalizeHost strips the port from a "host:port" target address, returning the bare
// host for use as a CA anchor's required DNS name. A value with no port is returned
// unchanged.
func normalizeHost(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}
