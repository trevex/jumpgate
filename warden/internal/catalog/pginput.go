package catalog

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// PostgresConfigInput is the proto-free domain form of a Postgres asset's config
// write. The handler converts the wire PostgresConfigInput (deriving each login's
// kind from its auth oneof arm and its secret source from the SecretAuth oneof)
// before calling the service.
type PostgresConfigInput struct {
	TargetAddress   string
	TargetServerCA  string
	DefaultDatabase string
	Logins          []PostgresLoginInput
}

// PostgresLoginInput is one persisted login write: its DB role, derived kind
// (mtls|password), and — for password — the secret source. Secret is nil for mtls.
type PostgresLoginInput struct {
	Role   string
	Kind   string
	Secret *SecretSource
}

// pgLoginRow is a persisted login: its role, derived kind (mtls|password), and the
// (optional) same-asset secret it references.
type pgLoginRow struct {
	role     string
	kind     string
	secretID pgtype.UUID
}

// resolvePostgresConfigInput maps a domain PostgresConfigInput to persisted rows
// within tx q. It seals inline new values into fresh asset_secrets and validates
// existing secret references. onCreate=true forbids existing_secret_id. It reuses
// resolveSecretSource (defined in sshinput.go) — the sealing boundary is shared.
func (s *Service) resolvePostgresConfigInput(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, in PostgresConfigInput, onCreate bool) ([]pgLoginRow, error) {
	rows := make([]pgLoginRow, 0, len(in.Logins))
	for _, l := range in.Logins {
		row := pgLoginRow{role: l.Role, kind: l.Kind}
		if l.Kind == "password" {
			id, err := s.resolveSecretSource(ctx, q, assetID, l.Role, l.Secret, onCreate)
			if err != nil {
				return nil, err
			}
			row.secretID = id
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// writePostgresConfig upserts the asset's connection config and replaces its login
// set with rows. A CHECK / composite-FK violation surfaces via the caller's
// apierr.MapWrite as InvalidArgument.
func writePostgresConfig(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, target, serverCA, defaultDB string, rows []pgLoginRow) error {
	if _, err := q.UpsertPostgresAssetConfig(ctx, sqlc.UpsertPostgresAssetConfigParams{
		AssetID:         assetID,
		TargetAddress:   target,
		TargetServerCa:  serverCA,
		DefaultDatabase: defaultDB,
	}); err != nil {
		return err
	}
	if err := q.DeletePostgresAssetLoginsForAsset(ctx, assetID); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := q.UpsertPostgresAssetLogin(ctx, sqlc.UpsertPostgresAssetLoginParams{
			AssetID:  assetID,
			Role:     r.role,
			Kind:     r.kind,
			SecretID: r.secretID,
		}); err != nil {
			return err
		}
	}
	return nil
}
