package session

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
)

// Handler implements sessionv1connect.SessionServiceHandler.
type Handler struct{ svc *Service }

// NewHandler constructs the SessionService implementation.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// CreateSession authorizes the caller to reach the asset (held-closure SSH-login
// check) and mints a data-plane admission token bound to the client's SSH key.
// Existence-hiding: an unentitled caller and an unknown asset both yield NotFound.
func (s *Handler) CreateSession(ctx context.Context, req *connect.Request[sessionv1.CreateSessionRequest]) (*connect.Response[sessionv1.CreateSessionResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	pub, err := parseSSHPublicKey(req.Msg.ClientSshPublicKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad client_ssh_public_key"))
	}
	fp := ssh.FingerprintSHA256(pub)
	out, err := s.svc.CreateSession(ctx, caller.ID, assetID, fp)
	switch {
	case errors.Is(err, ErrNoAccess):
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no session access"))
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&sessionv1.CreateSessionResponse{
		SessionToken:    out.Token,
		GatewayEndpoint: out.Endpoint,
		ExpiresAt:       timestamppb.New(out.ExpiresAt),
	}), nil
}

// CreateWebSession authorizes the caller to reach the asset via the given login
// (held-closure SSH-login check) and mints a short-lived browser-terminal
// admission ticket with no client-key binding. The caller is taken from the
// request context, which cookie and bearer auth both populate. Existence-hiding:
// an unentitled caller and an unknown asset both yield PermissionDenied.
func (s *Handler) CreateWebSession(ctx context.Context, req *connect.Request[sessionv1.CreateWebSessionRequest]) (*connect.Response[sessionv1.CreateWebSessionResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if req.Msg.Login == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("empty login"))
	}
	out, err := s.svc.CreateWebSession(ctx, caller.ID, assetID, req.Msg.Login)
	switch {
	case errors.Is(err, ErrNoAccess):
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("no session access"))
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&sessionv1.CreateWebSessionResponse{
		Ticket:          out.Token,
		GatewayEndpoint: out.Endpoint,
		ExpiresAt:       timestamppb.New(out.ExpiresAt),
	}), nil
}

// parseSSHPublicKey accepts the client public key in either OpenSSH
// authorized_keys text form or raw SSH wire form. It tries the authorized_keys
// parse first (what ssh.MarshalAuthorizedKey produces) and falls back to the
// wire parse (what ssh.PublicKey.Marshal produces).
func parseSSHPublicKey(raw []byte) (ssh.PublicKey, error) {
	if pub, _, _, _, err := ssh.ParseAuthorizedKey(raw); err == nil {
		return pub, nil
	}
	pub, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
