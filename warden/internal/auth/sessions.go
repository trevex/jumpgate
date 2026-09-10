package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// connectHeaderer is satisfied by every *connect.Request[T].
type connectHeaderer interface{ Header() http.Header }

// currentTokenID resolves the caller's own session id from their bearer/cookie
// token, so ListSessions can mark it and RevokeAllSessions can keep it.
func (s *Handler) currentTokenID(ctx context.Context, req connectHeaderer) (uuid.UUID, bool) {
	raw, _ := ExtractToken(req.Header())
	if raw == "" {
		return uuid.Nil, false
	}
	row, err := s.q.GetAuthTokenByHash(ctx, hashToken(raw))
	if err != nil {
		return uuid.Nil, false
	}
	return row.ID, true
}

// ListSessions returns the caller's active sessions.
func (s *Handler) ListSessions(ctx context.Context, req *connect.Request[authv1.ListSessionsRequest]) (*connect.Response[authv1.ListSessionsResponse], error) {
	u, ok := UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	rows, err := s.q.ListAuthTokensByUser(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	curID, _ := s.currentTokenID(ctx, req)
	out := make([]*authv1.Session, 0, len(rows))
	for _, r := range rows {
		out = append(out, &authv1.Session{
			Id:         r.ID.String(),
			CreatedAt:  timestamppb.New(r.CreatedAt),
			LastUsedAt: timestamppb.New(r.LastUsedAt),
			ExpiresAt:  timestamppb.New(r.ExpiresAt),
			ClientIp:   r.ClientIp.String,
			UserAgent:  r.UserAgent.String,
			Label:      r.Label.String,
			Current:    r.ID == curID,
		})
	}
	return connect.NewResponse(&authv1.ListSessionsResponse{Sessions: out}), nil
}

// RevokeSession revokes one of the caller's own sessions.
func (s *Handler) RevokeSession(ctx context.Context, req *connect.Request[authv1.RevokeSessionRequest]) (*connect.Response[authv1.RevokeSessionResponse], error) {
	u, ok := UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
	}
	n, err := s.q.DeleteAuthTokenByIDForUser(ctx, sqlc.DeleteAuthTokenByIDForUserParams{ID: id, UserID: u.ID})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if n == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("session not found"))
	}
	s.recordAudit(ctx, audit.Event{Type: EventSessionRevoked, ActorID: u.ID, Subject: "user:" + u.ID.String(), Details: jsonDetails(map[string]string{"session_id": id.String()})})
	return connect.NewResponse(&authv1.RevokeSessionResponse{}), nil
}

// RevokeAllSessions logs the caller out everywhere, optionally keeping current.
func (s *Handler) RevokeAllSessions(ctx context.Context, req *connect.Request[authv1.RevokeAllSessionsRequest]) (*connect.Response[authv1.RevokeAllSessionsResponse], error) {
	u, ok := UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	var n int64
	var err error
	if req.Msg.ExceptCurrent {
		raw, _ := ExtractToken(req.Header())
		n, err = s.tokens.RevokeAllExcept(ctx, u.ID, raw)
	} else {
		n, err = s.tokens.RevokeAll(ctx, u.ID)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.recordAudit(ctx, audit.Event{Type: EventSessionsRevoked, ActorID: u.ID, Subject: "user:" + u.ID.String(), Details: jsonDetails(map[string]string{"except_current": strconv.FormatBool(req.Msg.ExceptCurrent)})})
	return connect.NewResponse(&authv1.RevokeAllSessionsResponse{Revoked: n}), nil
}
