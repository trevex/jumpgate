package auth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

func TestSessionIssuer(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)

	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "issuer@x", DisplayName: "Issuer"})
	if err != nil {
		t.Fatal(err)
	}

	si := auth.NewSessionIssuer(tokens, true, time.Hour)
	tok, cookie, err := si.Issue(ctx, u.ID, auth.TokenMeta{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	if cookie.Name != auth.SessionCookie {
		t.Fatalf("cookie name = %q, want %q", cookie.Name, auth.SessionCookie)
	}
	if !cookie.HttpOnly {
		t.Fatal("cookie not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
	if !cookie.Secure {
		t.Fatal("cookie should be Secure when cookieSecure=true")
	}
	if want := int(time.Hour / time.Second); cookie.MaxAge != want {
		t.Fatalf("cookie MaxAge = %d, want %d", cookie.MaxAge, want)
	}

	gotUser, err := tokens.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if gotUser != u.ID {
		t.Fatalf("validate user = %v, want %v", gotUser, u.ID)
	}

	siInsecure := auth.NewSessionIssuer(tokens, false, time.Hour)
	_, cookie2, err := siInsecure.Issue(ctx, u.ID, auth.TokenMeta{})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cookie2.Secure {
		t.Fatal("cookie should not be Secure when cookieSecure=false")
	}
}
