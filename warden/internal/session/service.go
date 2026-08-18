package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
)

// ErrNoAccess is returned when the caller may not open a session to the asset —
// whether because the asset does not exist, is not SSH, or the caller holds no
// SSH login on it. The three are deliberately indistinguishable (existence-hiding).
var ErrNoAccess = errors.New("no session access to asset")

// Service authorizes and mints data-plane admission tokens.
type Service struct {
	q               *gen.Queries
	authz           authz.Authorizer
	minter          *sessiontoken.Minter
	gatewayEndpoint string
	ttl             time.Duration
}

// NewService builds the CreateSession domain service.
func NewService(q *gen.Queries, a authz.Authorizer, minter *sessiontoken.Minter, gatewayEndpoint string, ttl time.Duration) *Service {
	return &Service{q: q, authz: a, minter: minter, gatewayEndpoint: gatewayEndpoint, ttl: ttl}
}

// Created is the result of CreateSession.
type Created struct {
	Token     string
	Endpoint  string
	ExpiresAt time.Time
}

// CreateSession authorizes userID to reach assetID (≥1 SSH login via the held
// closure) and mints a token bound to clientKeyFingerprint. Existence-hiding: an
// unknown asset, a non-ssh asset, and a no-login asset all yield ErrNoAccess.
func (s *Service) CreateSession(ctx context.Context, userID, assetID uuid.UUID, clientKeyFingerprint string) (Created, error) {
	// GetSSHAssetConfig only exists for ssh assets with config; its absence (or the
	// asset's absence) means no SSH login is possible → hide behind ErrNoAccess.
	cfg, err := s.q.GetSSHAssetConfig(ctx, assetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Created{}, ErrNoAccess
	}
	if err != nil {
		return Created{}, err
	}
	logins, err := authz.EntitledLogins(ctx, s.authz, userID, assetID, cfg.AllowedLogins)
	if err != nil {
		return Created{}, err
	}
	if len(logins) == 0 {
		return Created{}, ErrNoAccess
	}
	sid := uuid.New()
	tok, err := s.minter.Mint(sessiontoken.Claims{
		SessionID: sid, UserID: userID, AssetID: assetID,
		Protocol: "ssh", ClientKeyFingerprint: clientKeyFingerprint,
	}, s.ttl)
	if err != nil {
		return Created{}, err
	}
	return Created{Token: tok, Endpoint: s.gatewayEndpoint, ExpiresAt: time.Now().Add(s.ttl)}, nil
}
