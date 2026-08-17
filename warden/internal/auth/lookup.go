package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// Lookup adapts the token service + queries to the interceptor's userLookup.
type Lookup struct {
	Tokens *TokenService
	Q      *gen.Queries
}

// Validate resolves a raw token to a user ID.
func (l Lookup) Validate(ctx context.Context, raw string) (uuid.UUID, error) {
	return l.Tokens.Validate(ctx, raw)
}

// Load hydrates a CurrentUser from the users table.
func (l Lookup) Load(ctx context.Context, id uuid.UUID) (CurrentUser, error) {
	u, err := l.Q.GetUserByID(ctx, id)
	if err != nil {
		return CurrentUser{}, fmt.Errorf("load user: %w", err)
	}
	return CurrentUser{ID: u.ID, Email: u.Email, IsAdmin: u.IsAdmin}, nil
}
