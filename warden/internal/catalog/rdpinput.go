package catalog

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// RDPConfigInput is the proto-free domain form of an RDP asset's config write. The
// handler converts the wire RDPConfigInput (deriving each login's kind from its auth
// oneof arm and its secret source from the SecretAuth oneof) before calling the
// service.
type RDPConfigInput struct {
	TargetAddress  string
	TargetServerCA string
	Logins         []RDPLoginInput
}

// RDPLoginInput is one persisted login write: its account name, derived kind
// (password today), and the secret source.
type RDPLoginInput struct {
	Login  string
	Kind   string
	Secret *SecretSource
}

// rdpLoginRow is a persisted login: its account name, kind (password), and the
// same-asset secret it references.
type rdpLoginRow struct {
	login    string
	kind     string
	secretID pgtype.UUID
}

// resolveRDPConfigInput maps a domain RDPConfigInput to persisted rows within tx q.
// It seals inline new values into fresh asset_secrets and validates existing secret
// references. onCreate=true forbids existing_secret_id. It reuses resolveSecretSource
// (defined in sshinput.go) — the sealing boundary is shared.
func (s *Service) resolveRDPConfigInput(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, in RDPConfigInput, onCreate bool) ([]rdpLoginRow, error) {
	rows := make([]rdpLoginRow, 0, len(in.Logins))
	for _, l := range in.Logins {
		row := rdpLoginRow{login: l.Login, kind: l.Kind}
		if l.Kind == "password" {
			id, err := s.resolveSecretSource(ctx, q, assetID, l.Login, l.Secret, onCreate)
			if err != nil {
				return nil, err
			}
			row.secretID = id
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// writeRDPConfig upserts the asset's connection config and replaces its login set
// with rows. A CHECK / composite-FK violation surfaces via the caller's
// apierr.MapWrite as InvalidArgument.
func writeRDPConfig(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, target, serverCA string, rows []rdpLoginRow) error {
	if _, err := q.UpsertRDPAssetConfig(ctx, sqlc.UpsertRDPAssetConfigParams{
		AssetID:        assetID,
		TargetAddress:  target,
		TargetServerCa: serverCA,
	}); err != nil {
		return err
	}
	if err := q.DeleteRDPAssetLoginsForAsset(ctx, assetID); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := q.UpsertRDPAssetLogin(ctx, sqlc.UpsertRDPAssetLoginParams{
			AssetID:  assetID,
			Login:    r.login,
			Kind:     r.kind,
			SecretID: r.secretID,
		}); err != nil {
			return err
		}
	}
	return nil
}
