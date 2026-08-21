package auth_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/auth"
)

func TestContextUserRoundTrip(t *testing.T) {
	u := auth.CurrentUser{ID: uuid.New(), Email: "a@x"}
	ctx := auth.WithUser(context.Background(), u)

	got, ok := auth.UserFromContext(ctx)
	if !ok {
		t.Fatal("no user in context")
	}
	if got.ID != u.ID || got.Email != u.Email {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	if _, ok := auth.UserFromContext(context.Background()); ok {
		t.Fatal("empty context should have no user")
	}
}
