package migrate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
)

// BackfillSSHTrustAnchors is the Go half of the 0007 SSH trust migration. It converts
// each SSH asset's pinned host_public_key into an approved migration-source trust
// anchor at the asset's current endpoint revision, so assets that were trusted by a
// pinned key stay verified once sessions require a current trust anchor.
//
// Fingerprinting and canonicalizing OpenSSH material cannot be done safely in SQL — a
// well-formed base64 blob that is not a real SSH key would otherwise be fingerprinted
// and trusted. This helper parses each key with golang.org/x/crypto/ssh and skips any
// empty or unparseable pin, so an invalid key is never trusted. It is idempotent:
// re-running inserts no duplicate anchor for a pin already migrated at that revision.
func BackfillSSHTrustAnchors(ctx context.Context, pool *pgxpool.Pool) error {
	type pin struct {
		assetID  uuid.UUID
		revision int64
		hostKey  string
	}
	rows, err := pool.Query(ctx, `
		SELECT c.asset_id, a.endpoint_revision, c.host_public_key
		FROM ssh_asset_config c
		JOIN assets a ON a.id = c.asset_id
		WHERE c.host_public_key <> ''`)
	if err != nil {
		return fmt.Errorf("read ssh pins: %w", err)
	}
	var pins []pin
	for rows.Next() {
		var p pin
		if err := rows.Scan(&p.assetID, &p.revision, &p.hostKey); err != nil {
			rows.Close()
			return fmt.Errorf("scan ssh pin: %w", err)
		}
		pins = append(pins, p)
	}
	rows.Close()
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
		// The anchor is auto-approved at migration time: approved_at defaults to now()
		// and approved_by is left NULL because the trust is migration-sourced (an
		// already-pinned key carried forward), not a human approval.
		if _, err := pool.Exec(ctx, `
			INSERT INTO target_trust_anchors
				(asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source)
			SELECT $1, $2, 'ssh_host_key', $3, $4, $5, 'migration'
			WHERE NOT EXISTS (
				SELECT 1 FROM target_trust_anchors
				WHERE asset_id = $1 AND endpoint_revision = $2
				  AND sha256_fingerprint = $4 AND source = 'migration' AND revoked_at IS NULL
			)`,
			p.assetID, p.revision, key.Type(), fingerprint, material); err != nil {
			return fmt.Errorf("insert migration anchor for asset %s: %w", p.assetID, err)
		}
	}
	return nil
}

// BackfillPostgresTrustAnchors is the Go half of the 0008 Postgres trust migration. It
// converts each postgres asset's configured target_server_ca PEM into an approved
// migration-source tls_ca trust anchor at the asset's current endpoint revision, with a
// required DNS name derived from the normalized target host, so assets that were trusted
// by a pinned server CA stay verified once sessions require a current trust anchor.
//
// Parsing and fingerprinting X.509 material cannot be done safely in SQL — a well-formed
// base64 blob that is not a real certificate would otherwise be fingerprinted and
// trusted. This helper parses each PEM with crypto/x509 and skips any empty or
// unparseable CA, so an invalid CA is never trusted (the asset stays pending until an
// operator probes and approves it). The fingerprint is the canonical "SHA256:" +
// raw-std-base64 over the CA certificate DER, matching the pg-proxy worker's
// FingerprintDER so the anchor compares equal to a session-time observed chain. It is
// idempotent: re-running inserts no duplicate anchor for a CA already migrated at that
// revision.
func BackfillPostgresTrustAnchors(ctx context.Context, pool *pgxpool.Pool) error {
	type conf struct {
		assetID  uuid.UUID
		revision int64
		target   string
		serverCA string
	}
	rows, err := pool.Query(ctx, `
		SELECT c.asset_id, a.endpoint_revision, c.target_address, c.target_server_ca
		FROM postgres_asset_config c
		JOIN assets a ON a.id = c.asset_id
		WHERE c.target_server_ca <> ''`)
	if err != nil {
		return fmt.Errorf("read postgres CAs: %w", err)
	}
	var confs []conf
	for rows.Next() {
		var c conf
		if err := rows.Scan(&c.assetID, &c.revision, &c.target, &c.serverCA); err != nil {
			rows.Close()
			return fmt.Errorf("scan postgres CA: %w", err)
		}
		confs = append(confs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate postgres CAs: %w", err)
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
		requiredDNS := []string{normalizeHost(c.target)}
		// The anchor is auto-approved at migration time: approved_at defaults to now()
		// and approved_by is left NULL because the trust is migration-sourced (an
		// already-pinned CA carried forward), not a human approval.
		if _, err := pool.Exec(ctx, `
			INSERT INTO target_trust_anchors
				(asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source, required_dns_names)
			SELECT $1, $2, 'tls_ca', $3, $4, $5, 'migration', $6
			WHERE NOT EXISTS (
				SELECT 1 FROM target_trust_anchors
				WHERE asset_id = $1 AND endpoint_revision = $2
				  AND sha256_fingerprint = $4 AND source = 'migration' AND revoked_at IS NULL
			)`,
			c.assetID, c.revision, strings.ToLower(cert.PublicKeyAlgorithm.String()), fingerprint, material, requiredDNS); err != nil {
			return fmt.Errorf("insert migration anchor for asset %s: %w", c.assetID, err)
		}
	}
	return nil
}

// BackfillRDPTrustAnchors is the Go half of the 0009 RDP trust migration. It follows
// BackfillPostgresTrustAnchors exactly, reading each rdp asset's configured
// target_server_ca PEM instead: it converts a valid pinned CA into an approved
// migration-source tls_ca trust anchor at the asset's current endpoint revision, with a
// required DNS name derived from the normalized target host, so assets that were trusted
// by a pinned server CA stay verified once sessions require a current trust anchor.
//
// As with the postgres migration, parsing and fingerprinting X.509 material stays in Go
// (an invalid or empty CA is never trusted — the asset stays pending until an operator
// probes and approves it). The fingerprint is the canonical "SHA256:" + raw-std-base64
// over the CA certificate DER, matching the rdp-proxy worker's fingerprint_der so the
// anchor compares equal to a session-time observed chain. Idempotent.
func BackfillRDPTrustAnchors(ctx context.Context, pool *pgxpool.Pool) error {
	type conf struct {
		assetID  uuid.UUID
		revision int64
		target   string
		serverCA string
	}
	rows, err := pool.Query(ctx, `
		SELECT c.asset_id, a.endpoint_revision, c.target_address, c.target_server_ca
		FROM rdp_asset_config c
		JOIN assets a ON a.id = c.asset_id
		WHERE c.target_server_ca <> ''`)
	if err != nil {
		return fmt.Errorf("read rdp CAs: %w", err)
	}
	var confs []conf
	for rows.Next() {
		var c conf
		if err := rows.Scan(&c.assetID, &c.revision, &c.target, &c.serverCA); err != nil {
			rows.Close()
			return fmt.Errorf("scan rdp CA: %w", err)
		}
		confs = append(confs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate rdp CAs: %w", err)
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
		requiredDNS := []string{normalizeHost(c.target)}
		if _, err := pool.Exec(ctx, `
			INSERT INTO target_trust_anchors
				(asset_id, endpoint_revision, kind, algorithm, sha256_fingerprint, public_material, source, required_dns_names)
			SELECT $1, $2, 'tls_ca', $3, $4, $5, 'migration', $6
			WHERE NOT EXISTS (
				SELECT 1 FROM target_trust_anchors
				WHERE asset_id = $1 AND endpoint_revision = $2
				  AND sha256_fingerprint = $4 AND source = 'migration' AND revoked_at IS NULL
			)`,
			c.assetID, c.revision, strings.ToLower(cert.PublicKeyAlgorithm.String()), fingerprint, material, requiredDNS); err != nil {
			return fmt.Errorf("insert migration anchor for asset %s: %w", c.assetID, err)
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
