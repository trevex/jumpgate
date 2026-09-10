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
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// ErrInvalidToken is returned when a token is unknown, revoked, or expired.
var ErrInvalidToken = errors.New("invalid token")

// TokenMeta is the per-session metadata captured at issue time for the session
// inventory. All fields are optional.
type TokenMeta struct {
	ClientIP  string
	UserAgent string
	Label     string
}

// TokenOption configures a TokenService.
type TokenOption func(*TokenService)

// WithIdleTTL enables idle-session expiry: a token unused for longer than d is
// rejected. Zero (the default) disables the idle check.
func WithIdleTTL(d time.Duration) TokenOption { return func(s *TokenService) { s.idleTTL = d } }

// touchInterval bounds how often Validate writes last_used_at, so an
// authenticated request storm does not become a write storm.
const touchInterval = time.Minute

// TokenService issues and validates opaque bearer tokens backed by Postgres.
// Only the SHA-256 hash of a token is stored, so tokens are revocable instantly.
type TokenService struct {
	q       *sqlc.Queries
	idleTTL time.Duration
}

// NewTokenService constructs a TokenService over the given queries.
func NewTokenService(q *sqlc.Queries, opts ...TokenOption) *TokenService {
	s := &TokenService{q: q}
	for _, o := range opts {
		o(s)
	}
	return s
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func text(v string) pgtype.Text {
	if v == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: v, Valid: true}
}

// Issue creates a token for userID valid for ttl and returns the raw token.
func (s *TokenService) Issue(ctx context.Context, userID uuid.UUID, ttl time.Duration, meta TokenMeta) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	if _, err := s.q.CreateAuthToken(ctx, sqlc.CreateAuthTokenParams{
		UserID:    userID,
		TokenHash: hashToken(raw),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(ttl), Valid: true},
		ClientIp:  text(meta.ClientIP),
		UserAgent: text(meta.UserAgent),
		Label:     text(meta.Label),
	}); err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}
	return raw, nil
}

// Validate returns the user ID for a valid, unexpired, non-idle token, or
// ErrInvalidToken. It lazily refreshes last_used_at at most once per
// touchInterval.
func (s *TokenService) Validate(ctx context.Context, raw string) (uuid.UUID, error) {
	h := hashToken(raw)
	row, err := s.q.GetAuthTokenByHash(ctx, h)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	now := time.Now()
	if row.ExpiresAt.Before(now) {
		return uuid.Nil, ErrInvalidToken
	}
	if s.idleTTL > 0 && now.After(row.LastUsedAt.Add(s.idleTTL)) {
		return uuid.Nil, ErrInvalidToken
	}
	if now.Sub(row.LastUsedAt) > touchInterval {
		_ = s.q.TouchAuthToken(ctx, h) // best-effort; a lost touch only shortens the idle window
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

// RevokeAll deletes every token for userID and returns the count.
func (s *TokenService) RevokeAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	return s.q.DeleteAuthTokensByUser(ctx, userID)
}

// RevokeAllExcept deletes every token for userID except the given raw token and
// returns the count.
func (s *TokenService) RevokeAllExcept(ctx context.Context, userID uuid.UUID, keepRaw string) (int64, error) {
	return s.q.DeleteAuthTokensByUserExcept(ctx, sqlc.DeleteAuthTokensByUserExceptParams{
		UserID:    userID,
		TokenHash: hashToken(keepRaw),
	})
}
