package migrate

import (
	"context"
	"fmt"
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
