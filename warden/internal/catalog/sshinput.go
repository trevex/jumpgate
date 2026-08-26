package catalog

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// SSHConfigInput is the proto-free domain form of an asset's SSH connection config
// write. The handler converts the wire SSHConfigInput (deriving each login's kind
// from its auth oneof arm and its secret source from the SecretAuth oneof) before
// calling the service.
type SSHConfigInput struct {
	HostPublicKey string
	TargetAddress string
	Logins        []SSHLoginInput
}

// SSHLoginInput is one persisted login write: its name, derived kind
// (ca|password|key), and — for password/key — the secret source. Secret is nil for
// a ca login.
type SSHLoginInput struct {
	Login  string
	Kind   string
	Secret *SecretSource
}

// SecretSource is the domain form of a SecretAuth: either an inline new value to be
// sealed, or a reference to an already-stored same-asset secret. Kind is "new" or
// "existing".
type SecretSource struct {
	Kind             string
	NewValue         []byte
	ExistingSecretID string
}

// sshLoginRow is a persisted login: its name, derived kind (ca|password|key), and
// the (optional) same-asset secret it references.
type sshLoginRow struct {
	login    string
	kind     string
	secretID pgtype.UUID
}

// resolveSSHConfigInput maps a domain SSHConfigInput to persisted rows within tx q.
// It seals inline new values into fresh asset_secrets and validates existing secret
// references. onCreate=true forbids existing_secret_id (a brand-new asset has no
// secrets).
func (s *Service) resolveSSHConfigInput(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, in SSHConfigInput, onCreate bool) ([]sshLoginRow, error) {
	rows := make([]sshLoginRow, 0, len(in.Logins))
	for _, l := range in.Logins {
		row := sshLoginRow{login: l.Login, kind: l.Kind}
		if l.Kind == "password" || l.Kind == "key" {
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

// resolveSecretSource turns a SecretSource into the same-asset secret id backing a
// password/key login. A new value is sealed into a fresh asset_secret (named per
// login, so re-onboarding a login rotates in place); an existing reference (forbidden
// on create) is validated to belong to the asset before use.
func (s *Service) resolveSecretSource(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, login string, sa *SecretSource, onCreate bool) (pgtype.UUID, error) {
	if sa == nil {
		return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": secret source required"))
	}
	switch sa.Kind {
	case "new":
		// Defense-in-depth: the proto edge (bytes.min_len = 1) rejects empty inline
		// secrets for real RPC callers, but in-process callers bypass the validation
		// interceptor. Guard here so an empty secret is never sealed.
		if len(sa.NewValue) == 0 {
			return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": empty secret"))
		}
		if s.sealer == nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
		}
		sealed, err := s.sealer.Seal(sa.NewValue)
		if err != nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeInternal, err)
		}
		row, err := q.SetAssetSecret(ctx, sqlc.SetAssetSecretParams{AssetID: assetID, Name: "login:" + login, Sealed: sealed})
		if err != nil {
			return pgtype.UUID{}, connect.NewError(connect.CodeInternal, err)
		}
		return pgUUID(row.ID), nil
	case "existing":
		if onCreate {
			return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": existing_secret_id cannot be used on create; use new_value"))
		}
		sid, err := uuid.Parse(sa.ExistingSecretID)
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
		return pgUUID(sid), nil
	default:
		return pgtype.UUID{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": secret source required"))
	}
}

// writeSSHConfig upserts the asset's connection config (host/target) and replaces
// its login set with rows. A CHECK / composite-FK violation surfaces via the
// caller's apierr.MapWrite as InvalidArgument.
func writeSSHConfig(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, hostKey, target string, rows []sshLoginRow) error {
	if _, err := q.UpsertSSHAssetConfig(ctx, sqlc.UpsertSSHAssetConfigParams{AssetID: assetID, HostPublicKey: hostKey, TargetAddress: target}); err != nil {
		return err
	}
	if err := q.DeleteSSHAssetLoginsForAsset(ctx, assetID); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := q.UpsertSSHAssetLogin(ctx, sqlc.UpsertSSHAssetLoginParams{AssetID: assetID, Login: r.login, Kind: r.kind, SecretID: r.secretID}); err != nil {
			return err
		}
	}
	return nil
}
