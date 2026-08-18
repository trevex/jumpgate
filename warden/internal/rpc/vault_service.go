package rpc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/pgerr"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
)

// VaultServer implements vaultv1connect.VaultServiceHandler: the admin API for
// certificate authorities, per-asset stored secrets, and SSH asset config.
//
// SECURITY: sealed private material never leaves the server. InitCA returns only
// the CA's public material; ListAssetSecrets returns metadata only (never the
// sealed value). A nil sealer means the vault is disabled: the write paths that
// need to seal plaintext fail FailedPrecondition rather than storing anything.
type VaultServer struct {
	q      *gen.Queries
	sealer *secrets.Sealer
}

// NewVaultServer constructs the VaultService implementation. A nil sealer
// disables the sealing write paths (vault disabled).
func NewVaultServer(q *gen.Queries, sealer *secrets.Sealer) *VaultServer {
	return &VaultServer{q: q, sealer: sealer}
}

// InitCA generates and seals a new active CA of the requested kind, returning
// its public material. A second init for the same kind hits the unique-active
// index and surfaces as AlreadyExists.
func (s *VaultServer) InitCA(ctx context.Context, req *connect.Request[vaultv1.InitCARequest]) (*connect.Response[vaultv1.InitCAResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
	}
	kind := req.Msg.Kind
	var (
		sealedPlaintext []byte
		publicMaterial  string
	)
	switch kind {
	case "ssh":
		seed, line, err := ca.GenerateSSHCA()
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		sealedPlaintext, publicMaterial = seed, line
	case "x509":
		keyDER, certPEM, err := ca.GenerateX509CA()
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		sealedPlaintext, publicMaterial = keyDER, certPEM
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported CA kind"))
	}
	sealed, err := s.sealer.Seal(sealedPlaintext)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	row, err := s.q.CreateCAKey(ctx, gen.CreateCAKeyParams{Kind: kind, Sealed: sealed, PublicMaterial: publicMaterial})
	if err != nil {
		return nil, mapWriteErr(err) // uq_active_ca violation → AlreadyExists
	}
	return connect.NewResponse(&vaultv1.InitCAResponse{PublicMaterial: row.PublicMaterial}), nil
}

// InitSessionKey generates and seals the active Ed25519 session-token signing
// key, returning its public half. A second init hits the unique-active index and
// surfaces as AlreadyExists. The running server loads the signing key once at
// boot, so a fresh deploy must restart warden after InitSessionKey to enable
// CreateSession/SetupSession.
func (s *VaultServer) InitSessionKey(ctx context.Context, _ *connect.Request[vaultv1.InitSessionKeyRequest]) (*connect.Response[vaultv1.InitSessionKeyResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
	}
	ks := session.NewKeyStore(s.q, s.sealer)
	if err := ks.Init(ctx); err != nil {
		if pgerr.IsUniqueViolation(err) {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("session signing key already initialized"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	_, pub, err := ks.LoadActive(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&vaultv1.InitSessionKeyResponse{PublicKey: pub}), nil
}

// GetCAPublic returns the active CA's public material for a kind.
func (s *VaultServer) GetCAPublic(ctx context.Context, req *connect.Request[vaultv1.GetCAPublicRequest]) (*connect.Response[vaultv1.GetCAPublicResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	row, err := s.q.GetActiveCA(ctx, req.Msg.Kind)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no active CA"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&vaultv1.GetCAPublicResponse{PublicMaterial: row.PublicMaterial}), nil
}

// SetAssetSecret seals and stores a named secret for an asset (upsert by name).
func (s *VaultServer) SetAssetSecret(ctx context.Context, req *connect.Request[vaultv1.SetAssetSecretRequest]) (*connect.Response[vaultv1.SetAssetSecretResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	sealed, err := s.sealer.Seal(req.Msg.Value)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	row, err := s.q.SetAssetSecret(ctx, gen.SetAssetSecretParams{AssetID: assetID, Name: req.Msg.Name, Sealed: sealed})
	if err != nil {
		return nil, mapWriteErr(err) // bad asset FK → InvalidArgument
	}
	return connect.NewResponse(&vaultv1.SetAssetSecretResponse{Id: row.ID.String()}), nil
}

// DeleteAssetSecret removes a stored secret by id. Deleting a non-existent id is
// a no-op.
func (s *VaultServer) DeleteAssetSecret(ctx context.Context, req *connect.Request[vaultv1.DeleteAssetSecretRequest]) (*connect.Response[vaultv1.DeleteAssetSecretResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteAssetSecret(ctx, id); err != nil {
		// A secret still referenced by an ssh_asset_config (ON DELETE RESTRICT) is a
		// client-fixable precondition, not an Internal error.
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&vaultv1.DeleteAssetSecretResponse{}), nil
}

// ListAssetSecrets returns the metadata (id, name, created_at) of an asset's
// stored secrets. The sealed value is NEVER returned.
func (s *VaultServer) ListAssetSecrets(ctx context.Context, req *connect.Request[vaultv1.ListAssetSecretsRequest]) (*connect.Response[vaultv1.ListAssetSecretsResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	rows, err := s.q.ListAssetSecrets(ctx, assetID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &vaultv1.ListAssetSecretsResponse{}
	for i := range rows {
		out.Secrets = append(out.Secrets, &vaultv1.AssetSecretMeta{
			Id:        rows[i].ID.String(),
			Name:      rows[i].Name,
			CreatedAt: rows[i].CreatedAt.Format(time.RFC3339),
		})
	}
	return connect.NewResponse(out), nil
}

// SetSSHAssetConfig upserts an asset's SSH credential config. The
// stored_key_needs_secret CHECK and the stored_secret_id FK surface as
// InvalidArgument.
func (s *VaultServer) SetSSHAssetConfig(ctx context.Context, req *connect.Request[vaultv1.SetSSHAssetConfigRequest]) (*connect.Response[vaultv1.SetSSHAssetConfigResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	storedSecret, _, err := optUUID(req.Msg.StoredSecretId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad stored_secret_id"))
	}
	if _, err := s.q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{
		AssetID:        assetID,
		AllowedLogins:  req.Msg.AllowedLogins,
		AuthMethod:     req.Msg.AuthMethod,
		StoredSecretID: storedSecret,
	}); err != nil {
		return nil, mapWriteErr(err) // CHECK / FK → InvalidArgument
	}
	return connect.NewResponse(&vaultv1.SetSSHAssetConfigResponse{}), nil
}

// GetSSHAssetConfig returns an asset's SSH credential config; NotFound if absent.
func (s *VaultServer) GetSSHAssetConfig(ctx context.Context, req *connect.Request[vaultv1.GetSSHAssetConfigRequest]) (*connect.Response[vaultv1.GetSSHAssetConfigResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	cfg, err := s.q.GetSSHAssetConfig(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no ssh asset config"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&vaultv1.GetSSHAssetConfigResponse{
		AllowedLogins:  cfg.AllowedLogins,
		AuthMethod:     cfg.AuthMethod,
		StoredSecretId: pgUUIDToString(cfg.StoredSecretID),
	}), nil
}
