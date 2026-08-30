package enrollment

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	enrollmentv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// Handler adapts Service to the generated EnrollmentServiceHandler interface.
type Handler struct {
	svc   *Service
	guard apiguard.Guard
}

// NewHandler constructs the transport Handler over svc and guard.
func NewHandler(svc *Service, guard apiguard.Guard) *Handler {
	return &Handler{svc: svc, guard: guard}
}

// caller extracts the authenticated user's id from ctx (mirrors catalog.caller).
func caller(ctx context.Context) (uuid.UUID, error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return uuid.Nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return u.ID, nil
}

// CreateEnrollmentToken mints a token for an asset; caller needs
// catalog:asset:update on the asset (mirrors UpdateAssetConfig gating).
func (h *Handler) CreateEnrollmentToken(ctx context.Context, req *connect.Request[enrollmentv1.CreateEnrollmentTokenRequest]) (*connect.Response[enrollmentv1.CreateEnrollmentTokenResponse], error) {
	assetID, err := uuid.Parse(req.Msg.GetAssetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "catalog:asset:update", authz.AssetScope(assetID)); err != nil {
		return nil, err
	}
	raw, exp, err := h.svc.Mint(ctx, assetID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&enrollmentv1.CreateEnrollmentTokenResponse{
		Token:     raw,
		ExpiresAt: exp.UTC().Format(time.RFC3339),
	}), nil
}

// SignAgentCert consumes the enrollment token and signs the CSR. No bearer: the
// token itself is the credential.
func (h *Handler) SignAgentCert(ctx context.Context, req *connect.Request[enrollmentv1.SignAgentCertRequest]) (*connect.Response[enrollmentv1.SignAgentCertResponse], error) {
	certPEM, bundlePEM, err := h.svc.SignAgentCert(ctx, req.Msg.GetEnrollmentToken(), req.Msg.GetCsrPem())
	switch {
	case errors.Is(err, ErrInvalidToken):
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid enrollment token"))
	case errors.Is(err, ErrNoMeshCA):
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("mesh CA not provisioned"))
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&enrollmentv1.SignAgentCertResponse{
		CertPem:     certPEM,
		CaBundlePem: bundlePEM,
	}), nil
}
