package rpc

import (
	"context"
	"encoding/pem"
	"errors"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/postgres/pgerr"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
)

// meshCertTTL is the validity window of an issued mesh leaf certificate.
const meshCertTTL = 90 * 24 * time.Hour

// VaultServer implements vaultv1connect.VaultServiceHandler: the admin API for
// certificate authorities, per-asset stored secrets, and SSH asset config.
//
// SECURITY: sealed private material never leaves the server. InitCA returns only
// the CA's public material; ListAssetSecrets returns metadata only (never the
// sealed value). A nil sealer means the vault is disabled: the write paths that
// need to seal plaintext fail FailedPrecondition rather than storing anything.
type VaultServer struct {
	q      *sqlc.Queries
	sealer *secrets.Sealer
	capGuard
}

// NewVaultServer constructs the VaultService implementation. A nil sealer
// disables the sealing write paths (vault disabled).
func NewVaultServer(q *sqlc.Queries, sealer *secrets.Sealer, a authz.Authorizer) *VaultServer {
	return &VaultServer{q: q, sealer: sealer, capGuard: capGuard{authz: a, q: q}}
}

// InitCA generates and seals a new active CA of the requested kind, returning
// its public material. A second init for the same kind hits the unique-active
// index and surfaces as AlreadyExists.
func (s *VaultServer) InitCA(ctx context.Context, req *connect.Request[vaultv1.InitCARequest]) (*connect.Response[vaultv1.InitCAResponse], error) {
	if err := s.requireCap(ctx, "vault:ca:init", authz.GlobalScope()); err != nil {
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
	row, err := s.q.CreateCAKey(ctx, sqlc.CreateCAKeyParams{Kind: kind, Sealed: sealed, PublicMaterial: publicMaterial})
	if err != nil {
		return nil, mapWriteErr(err) // uq_active_ca violation → AlreadyExists
	}
	return connect.NewResponse(&vaultv1.InitCAResponse{PublicMaterial: row.PublicMaterial}), nil
}

// InitMeshCA generates and seals the dedicated internal mesh mTLS CA, returning
// its certificate PEM (public trust material). A second init hits the
// unique-active index and surfaces as AlreadyExists. The sealed private key
// never leaves the server.
func (s *VaultServer) InitMeshCA(ctx context.Context, _ *connect.Request[vaultv1.InitMeshCARequest]) (*connect.Response[vaultv1.InitMeshCAResponse], error) {
	if err := s.requireCap(ctx, "vault:ca:init", authz.GlobalScope()); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
	}
	keyDER, certPEM, err := ca.GenerateMeshCA()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	sealed, err := s.sealer.Seal(keyDER)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if _, err := s.q.CreateCAKey(ctx, sqlc.CreateCAKeyParams{Kind: "mesh", Sealed: sealed, PublicMaterial: string(certPEM)}); err != nil {
		return nil, mapWriteErr(err) // uq_active_ca violation → AlreadyExists
	}
	return connect.NewResponse(&vaultv1.InitMeshCAResponse{CaCertPem: certPEM}), nil
}

// IssueMeshCert signs a client-generated CSR into a mesh leaf certificate whose
// URI SAN is stamped from the trusted spiffe_id (never from the CSR). The client
// keeps its private key; only the leaf cert and CA bundle are returned. Requires
// an already-initialized mesh CA (else FailedPrecondition).
func (s *VaultServer) IssueMeshCert(ctx context.Context, req *connect.Request[vaultv1.IssueMeshCertRequest]) (*connect.Response[vaultv1.IssueMeshCertResponse], error) {
	if err := s.requireCap(ctx, "vault:ca:issue", authz.GlobalScope()); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
	}
	// Validate the spiffe id shape (defense in depth over ca.SignCSR).
	u, err := url.Parse(req.Msg.SpiffeId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad spiffe_id"))
	}
	if _, err := mesh.ParseIdentity(u); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	row, err := s.q.GetActiveCA(ctx, "mesh")
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("mesh CA not initialized"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	keyDER, err := s.sealer.Open(row.Sealed)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	mca, err := ca.LoadMeshCA(keyDER, []byte(row.PublicMaterial))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	blk, _ := pem.Decode(req.Msg.CsrPem)
	if blk == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad csr pem"))
	}
	leafPEM, bundlePEM, err := mca.SignCSR(blk.Bytes, req.Msg.SpiffeId, meshCertTTL)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&vaultv1.IssueMeshCertResponse{CertPem: leafPEM, CaBundlePem: bundlePEM}), nil
}

// InitSessionKey generates and seals the active Ed25519 session-token signing
// key, returning its public half. A second init hits the unique-active index and
// surfaces as AlreadyExists. The running server loads the signing key once at
// boot, so a fresh deploy must restart warden after InitSessionKey to enable
// CreateSession/SetupSession.
func (s *VaultServer) InitSessionKey(ctx context.Context, _ *connect.Request[vaultv1.InitSessionKeyRequest]) (*connect.Response[vaultv1.InitSessionKeyResponse], error) {
	if err := s.requireCap(ctx, "vault:key:init", authz.GlobalScope()); err != nil {
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
	if err := s.requireCap(ctx, "vault:ca:read", authz.GlobalScope()); err != nil {
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
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if err := s.requireCap(ctx, "vault:secret:write", authz.AssetScope(assetID)); err != nil {
		return nil, err
	}
	if s.sealer == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("vault not configured"))
	}
	sealed, err := s.sealer.Seal(req.Msg.Value)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	row, err := s.q.SetAssetSecret(ctx, sqlc.SetAssetSecretParams{AssetID: assetID, Name: req.Msg.Name, Sealed: sealed})
	if err != nil {
		return nil, mapWriteErr(err) // bad asset FK → InvalidArgument
	}
	return connect.NewResponse(&vaultv1.SetAssetSecretResponse{Id: row.ID.String()}), nil
}

// DeleteAssetSecret removes a stored secret by id. Deleting a non-existent id is
// a no-op.
func (s *VaultServer) DeleteAssetSecret(ctx context.Context, req *connect.Request[vaultv1.DeleteAssetSecretRequest]) (*connect.Response[vaultv1.DeleteAssetSecretResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	// Derive the owning asset for capability scoping. A missing secret is a no-op
	// (delete-of-nonexistent), but we still require the global write cap to avoid
	// letting an unscoped caller probe id existence via timing/behavior.
	sec, err := s.q.GetAssetSecretByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if err := s.requireCap(ctx, "vault:secret:write", authz.GlobalScope()); err != nil {
				return nil, err
			}
			return connect.NewResponse(&vaultv1.DeleteAssetSecretResponse{}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.requireCap(ctx, "vault:secret:write", authz.AssetScope(sec.AssetID)); err != nil {
		return nil, err
	}
	if err := s.q.DeleteAssetSecret(ctx, id); err != nil {
		// A secret still referenced by an ssh_asset_config (ON DELETE RESTRICT) is a
		// client-fixable precondition, not an Internal error.
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&vaultv1.DeleteAssetSecretResponse{}), nil
}

// ListAssetSecrets returns the metadata (id, name, created_at) of an asset's
// stored secrets ordered by (name ASC, id ASC) with keyset pagination.
// The sealed value is NEVER returned.
func (s *VaultServer) ListAssetSecrets(ctx context.Context, req *connect.Request[vaultv1.ListAssetSecretsRequest]) (*connect.Response[vaultv1.ListAssetSecretsResponse], error) {
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if err := s.requireCap(ctx, "vault:secret:read", authz.AssetScope(assetID)); err != nil {
		return nil, err
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := sqlc.ListAssetSecretsParams{AssetID: assetID, Lim: limit}
	if k != nil {
		params.AfterName = pgtype.Text{String: k.Name, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListAssetSecrets(ctx, params)
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
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeNameToken(last.Name, last.ID)
	}
	return connect.NewResponse(out), nil
}
