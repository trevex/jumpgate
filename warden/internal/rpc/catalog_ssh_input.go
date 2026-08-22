package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// sshLoginRow is a persisted login: its name, derived kind (ca|password|key), and
// the (optional) same-asset secret it references.
type sshLoginRow struct {
	login    string
	kind     string
	secretID pgtype.UUID
}

// resolveSSHConfigInput maps a write-only SSHConfigInput to persisted rows within tx
// q. It seals inline new_value into a fresh asset_secret and validates
// existing_secret_id. onCreate=true forbids existing_secret_id (a brand-new asset has
// no secrets). The login kind is derived server-side from the auth oneof arm.
func (s *CatalogServer) resolveSSHConfigInput(ctx context.Context, q *gen.Queries, assetID uuid.UUID, in *catalogv1.SSHConfigInput, onCreate bool) ([]sshLoginRow, error) {
	rows := make([]sshLoginRow, 0, len(in.GetLogins()))
	for _, l := range in.GetLogins() {
		row := sshLoginRow{login: l.GetLogin()}
		switch a := l.GetAuth().(type) {
		case *catalogv1.SSHLoginInput_Ca:
			row.kind = "ca"
		case *catalogv1.SSHLoginInput_Password:
			row.kind = "password"
			id, err := s.resolveSecretSource(ctx, q, assetID, l.GetLogin(), a.Password, onCreate)
			if err != nil {
				return nil, err
			}
			row.secretID = id
		case *catalogv1.SSHLoginInput_Key:
			row.kind = "key"
			id, err := s.resolveSecretSource(ctx, q, assetID, l.GetLogin(), a.Key, onCreate)
			if err != nil {
				return nil, err
			}
			row.secretID = id
		default:
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+l.GetLogin()+": auth kind required"))
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// resolveSecretSource turns a SecretAuth into the same-asset secret id backing a
// password/key login. new_value is sealed into a fresh asset_secret (named per
// login, so re-onboarding a login rotates in place); existing_secret_id references
// an already-stored secret (forbidden on create) and is validated to belong to the
// asset before use.
func (s *CatalogServer) resolveSecretSource(ctx context.Context, q *gen.Queries, assetID uuid.UUID, login string, sa *catalogv1.SecretAuth, onCreate bool) (pgtype.UUID, error) {
	switch src := sa.GetSource().(type) {
	case *catalogv1.SecretAuth_NewValue:
		if s.sealer == nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
		}
		sealed, err := s.sealer.Seal(src.NewValue)
		if err != nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeInternal, err)
		}
		row, err := q.SetAssetSecret(ctx, gen.SetAssetSecretParams{AssetID: assetID, Name: "login:" + login, Sealed: sealed})
		if err != nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeInternal, err)
		}
		return pgtype.UUID{Bytes: row.ID, Valid: true}, nil
	case *catalogv1.SecretAuth_ExistingSecretId:
		if onCreate {
			return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": existing_secret_id cannot be used on create; use new_value"))
		}
		sid, err := uuid.Parse(src.ExistingSecretId)
		if err != nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": invalid existing_secret_id"))
		}
		sec, err := q.GetAssetSecretByID(ctx, sid)
		if err != nil {
			return pgtype.UUID{}, notFoundOrInternal(err)
		}
		// The secret must belong to this asset; a cross-asset reference is rejected
		// (the composite FK would also catch it at write time, but failing early gives
		// a clear InvalidArgument rather than a mapped constraint error).
		if sec.AssetID != assetID {
			return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": existing_secret_id does not belong to this asset"))
		}
		return pgtype.UUID{Bytes: sid, Valid: true}, nil
	default:
		return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": secret source required"))
	}
}

// writeSSHConfig upserts the asset's connection config (host/target) and replaces
// its login set with rows. A CHECK / composite-FK violation surfaces via the
// caller's mapWriteErr as InvalidArgument.
func writeSSHConfig(ctx context.Context, q *gen.Queries, assetID uuid.UUID, hostKey, target string, rows []sshLoginRow) error {
	if _, err := q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{AssetID: assetID, HostPublicKey: hostKey, TargetAddress: target}); err != nil {
		return err
	}
	if err := q.DeleteSSHAssetLoginsForAsset(ctx, assetID); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{AssetID: assetID, Login: r.login, Kind: r.kind, SecretID: r.secretID}); err != nil {
			return err
		}
	}
	return nil
}
