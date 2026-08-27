package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
)

// webTTL bounds a browser-terminal admission ticket. It is short because the
// gateway redeems it immediately on WebSocket open; there is no client key to
// bind, so the tight window is the ticket's primary protection.
const webTTL = 60 * time.Second

// ErrNoAccess is returned when the caller may not open a session to the asset —
// whether because the asset does not exist, is not SSH, or the caller holds no
// SSH login on it. The three are deliberately indistinguishable (existence-hiding).
var ErrNoAccess = errors.New("no session access to asset")

// Service authorizes and mints data-plane admission tokens.
type Service struct {
	q               *sqlc.Queries
	authz           *authz.Authorizer
	minter          *sessiontoken.Minter
	gatewayEndpoint string
	ttl             time.Duration
}

// NewService builds the CreateSession domain service.
func NewService(q *sqlc.Queries, a *authz.Authorizer, minter *sessiontoken.Minter, gatewayEndpoint string, ttl time.Duration) *Service {
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
	if _, err := s.entitledLogins(ctx, userID, assetID); err != nil {
		return Created{}, err
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

// CreateWebSession authorizes userID to reach assetID via the given login and
// mints a short-lived browser-terminal admission ticket (mode=web, no client
// key). The entitlement check is identical to CreateSession; additionally login
// must be one of the caller's entitled logins on the asset. Existence-hiding:
// an unknown asset, a non-ssh asset, a no-login asset, and an unentitled login
// all yield ErrNoAccess.
func (s *Service) CreateWebSession(ctx context.Context, userID, assetID uuid.UUID, login string) (Created, error) {
	logins, err := s.entitledLogins(ctx, userID, assetID)
	if err != nil {
		return Created{}, err
	}
	if !contains(logins, login) {
		return Created{}, ErrNoAccess
	}
	sid := uuid.New()
	tok, err := s.minter.Mint(sessiontoken.Claims{
		SessionID: sid, UserID: userID, AssetID: assetID,
		Protocol: "ssh", Mode: "web", Login: login, ClientKeyFingerprint: "",
	}, webTTL)
	if err != nil {
		return Created{}, err
	}
	return Created{Token: tok, Endpoint: s.gatewayEndpoint, ExpiresAt: time.Now().Add(webTTL)}, nil
}

// entitledLogins returns the caller's entitled SSH logins on the asset, or
// ErrNoAccess when the asset yields no reachable login (unknown/non-ssh asset,
// or the caller holds no ssh:login capability). The two Create paths share it so
// their authz stays in lockstep.
func (s *Service) entitledLogins(ctx context.Context, userID, assetID uuid.UUID) ([]string, error) {
	// The asset's configured SSH logins exist only for ssh assets; an empty set
	// (non-ssh asset, unknown asset, or an ssh asset with no logins) means no SSH
	// login is possible → hide behind ErrNoAccess.
	rows, err := s.q.ListSSHAssetLogins(ctx, assetID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNoAccess
	}
	allowed := make([]string, 0, len(rows))
	for _, r := range rows {
		allowed = append(allowed, r.Login)
	}
	logins, err := authz.EntitledLogins(ctx, s.authz, userID, assetID, allowed)
	if err != nil {
		return nil, err
	}
	if len(logins) == 0 {
		return nil, ErrNoAccess
	}
	return logins, nil
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
