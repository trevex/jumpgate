package auth_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/auth"
)

func TestContextUserRoundTrip(t *testing.T) {
	u := auth.CurrentUser{ID: uuid.New(), Email: "a@x", IsAdmin: true}
	ctx := auth.WithUser(context.Background(), u)

	got, ok := auth.UserFromContext(ctx)
	if !ok {
		t.Fatal("no user in context")
	}
	if got.ID != u.ID || !got.IsAdmin {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	if _, ok := auth.UserFromContext(context.Background()); ok {
		t.Fatal("empty context should have no user")
	}
}

func TestRequireAdmin(t *testing.T) {
	// no user -> error
	if err := auth.RequireAdmin(context.Background()); err == nil {
		t.Fatal("RequireAdmin with no user should error")
	}
	// non-admin -> error
	ctx := auth.WithUser(context.Background(), auth.CurrentUser{ID: uuid.New(), IsAdmin: false})
	if err := auth.RequireAdmin(ctx); err == nil {
		t.Fatal("RequireAdmin for non-admin should error")
	}
	// admin -> nil
	ctx = auth.WithUser(context.Background(), auth.CurrentUser{ID: uuid.New(), IsAdmin: true})
	if err := auth.RequireAdmin(ctx); err != nil {
		t.Fatalf("RequireAdmin for admin should pass, got %v", err)
	}
}
