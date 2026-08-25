package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// ErrInvalidToken is returned when a token is unknown, revoked, or expired.
var ErrInvalidToken = errors.New("invalid token")

// TokenService issues and validates opaque bearer tokens backed by Postgres.
// Only the SHA-256 hash of a token is stored, so tokens are revocable instantly.
type TokenService struct {
	q *sqlc.Queries
}

// NewTokenService constructs a TokenService over the given queries.
func NewTokenService(q *sqlc.Queries) *TokenService {
	return &TokenService{q: q}
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// Issue creates a token for userID valid for ttl and returns the raw token.
func (s *TokenService) Issue(ctx context.Context, userID uuid.UUID, ttl time.Duration) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	if _, err := s.q.CreateAuthToken(ctx, sqlc.CreateAuthTokenParams{
		UserID:    userID,
		TokenHash: hashToken(raw),
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}
	return raw, nil
}

// Validate returns the user ID for a valid, unexpired token, or ErrInvalidToken.
func (s *TokenService) Validate(ctx context.Context, raw string) (uuid.UUID, error) {
	row, err := s.q.GetAuthTokenByHash(ctx, hashToken(raw))
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	if row.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, ErrInvalidToken
	}
	return row.UserID, nil
}

// Revoke deletes the token so it can no longer be used.
func (s *TokenService) Revoke(ctx context.Context, raw string) error {
	if err := s.q.DeleteAuthToken(ctx, hashToken(raw)); err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	return nil
}
