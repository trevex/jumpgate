package auth_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// mustLogin logs in against h and returns the raw bearer token.
func mustLogin(t *testing.T, h *auth.Handler, email, pw string) string {
	t.Helper()
	resp, err := h.Login(context.Background(), connect.NewRequest(&authv1.LoginRequest{Email: email, Password: pw}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return resp.Msg.Token
}

// authedRequest builds a connect request carrying tok as the bearer token.
func authedRequest[T any](tok string, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+tok)
	return req
}

func TestListSessionsMarksCurrent(t *testing.T) {
	h, _, uid, _ := newLoginHarness(t, "sessions1@x", "a-perfectly-fine-passphrase")
	tok1 := mustLogin(t, h, "sessions1@x", "a-perfectly-fine-passphrase")
	mustLogin(t, h, "sessions1@x", "a-perfectly-fine-passphrase")

	ctx := auth.WithUser(context.Background(), auth.CurrentUser{ID: uid})
	resp, err := h.ListSessions(ctx, authedRequest(tok1, &authv1.ListSessionsRequest{}))
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(resp.Msg.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(resp.Msg.Sessions))
	}
	currentCount := 0
	for _, s := range resp.Msg.Sessions {
		if s.Current {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Fatalf("current sessions = %d, want 1", currentCount)
	}
}

func TestRevokeAllExceptCurrent(t *testing.T) {
	h, _, uid, _ := newLoginHarness(t, "sessions2@x", "a-perfectly-fine-passphrase")
	tokKeep := mustLogin(t, h, "sessions2@x", "a-perfectly-fine-passphrase")
	mustLogin(t, h, "sessions2@x", "a-perfectly-fine-passphrase")

	ctx := auth.WithUser(context.Background(), auth.CurrentUser{ID: uid})
	resp, err := h.RevokeAllSessions(ctx, authedRequest(tokKeep, &authv1.RevokeAllSessionsRequest{ExceptCurrent: true}))
	if err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if resp.Msg.Revoked != 1 {
		t.Fatalf("revoked = %d, want 1", resp.Msg.Revoked)
	}

	listResp, err := h.ListSessions(ctx, authedRequest(tokKeep, &authv1.ListSessionsRequest{}))
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(listResp.Msg.Sessions) != 1 {
		t.Fatalf("remaining sessions = %d, want 1", len(listResp.Msg.Sessions))
	}
	if !listResp.Msg.Sessions[0].Current {
		t.Fatalf("kept session should be the current one: %+v", listResp.Msg.Sessions[0])
	}
}

func TestRevokeSessionNotFoundForOtherUser(t *testing.T) {
	h, q, uidA, _ := newLoginHarness(t, "sessionsA@x", "a-perfectly-fine-passphrase")
	tokA := mustLogin(t, h, "sessionsA@x", "a-perfectly-fine-passphrase")

	// Seed a second user on the same handler/pool.
	uB, err := q.CreateUserFull(context.Background(), sqlc.CreateUserFullParams{Email: "sessionsB@x", DisplayName: "sessionsB@x"})
	if err != nil {
		t.Fatalf("create user b: %v", err)
	}
	hash, err := auth.HashPassword("a-perfectly-fine-passphrase")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := q.SetUserPassword(context.Background(), sqlc.SetUserPasswordParams{ID: uB.ID, PasswordHash: hash}); err != nil {
		t.Fatalf("set password b: %v", err)
	}

	ctxA := auth.WithUser(context.Background(), auth.CurrentUser{ID: uidA})
	listResp, err := h.ListSessions(ctxA, authedRequest(tokA, &authv1.ListSessionsRequest{}))
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(listResp.Msg.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(listResp.Msg.Sessions))
	}
	sessionIDOfA := listResp.Msg.Sessions[0].Id

	ctxB := auth.WithUser(context.Background(), auth.CurrentUser{ID: uB.ID})
	_, err = h.RevokeSession(ctxB, connect.NewRequest(&authv1.RevokeSessionRequest{Id: sessionIDOfA}))
	if err == nil {
		t.Fatal("expected error revoking another user's session")
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("code = %v, want NotFound", connect.CodeOf(err))
	}
}
