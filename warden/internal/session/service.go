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

// k8sTTL bounds a kubernetes admission token (longer than webTTL: kubectl exec
// plugins cache and reuse the token across a session, not just a single redeem).
const k8sTTL = 15 * time.Minute

// ErrNoAccess is returned when the caller may not open a session to the asset —
// whether because the asset does not exist, is not SSH, or the caller holds no
// SSH login on it. The three are deliberately indistinguishable (existence-hiding).
var ErrNoAccess = errors.New("no session access to asset")

// ErrClusterOffline means the user is entitled but no broker currently holds the
// cluster's agent tunnel.
var ErrClusterOffline = errors.New("cluster has no connected agent")

// brokerLocator resolves which broker currently holds an asset's agent tunnel.
// Defined here (not imported from dataplane) to avoid a session↔dataplane import
// cycle; *dataplane.Registry satisfies it structurally.
type brokerLocator interface {
	BrokerForAsset(assetID string) (string, bool)
}

// Service authorizes and mints data-plane admission tokens.
type Service struct {
	q               *sqlc.Queries
	authz           *authz.Authorizer
	minter          *sessiontoken.Minter
	gatewayEndpoint string
	// insecureEndpoint is the plaintext (ws://) gateway address handed to a browser
	// when insecure sessions are allowed AND requested. Empty disables the path.
	insecureEndpoint string
	// allowInsecure gates the insecure endpoint. Default false → an insecure
	// request is silently downgraded to the secure endpoint (fail-closed).
	allowInsecure bool
	ttl           time.Duration
	brokers       brokerLocator
}

// NewService builds the CreateSession domain service. insecureEndpoint/allowInsecure
// are DEV-ONLY: unless allowInsecure is true and insecureEndpoint is non-empty, a
// browser's insecure request is downgraded to the secure endpoint (fail-closed).
// brokers resolves the broker currently holding a k8s asset's agent tunnel
// (CreateKubernetesSession); the shared *dataplane.Registry satisfies it.
func NewService(q *sqlc.Queries, a *authz.Authorizer, minter *sessiontoken.Minter, gatewayEndpoint, insecureEndpoint string, allowInsecure bool, ttl time.Duration, brokers brokerLocator) *Service {
	return &Service{
		q:                q,
		authz:            a,
		minter:           minter,
		gatewayEndpoint:  gatewayEndpoint,
		insecureEndpoint: insecureEndpoint,
		allowInsecure:    allowInsecure,
		ttl:              ttl,
		brokers:          brokers,
	}
}

// Created is the result of CreateSession.
type Created struct {
	Token     string
	Endpoint  string
	ExpiresAt time.Time
	// Insecure is true only when a web session was actually granted the plaintext
	// endpoint (allowed AND requested). The browser uses it to pick ws:// vs wss://.
	Insecure bool
	// DefaultDatabase is the postgres asset's default database name. Empty for
	// non-postgres sessions (ssh CreateSession/CreateWebSession).
	DefaultDatabase string
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
func (s *Service) CreateWebSession(ctx context.Context, userID, assetID uuid.UUID, login string, insecure bool) (Created, error) {
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
	// Fail-closed endpoint selection: only a browser that both asked for insecure
	// AND runs against a warden that allows it (with an endpoint configured) gets
	// the plaintext endpoint. Otherwise it is silently downgraded to secure. The
	// ticket itself is identical either way — only transport TLS differs.
	endpoint, isInsecure := s.gatewayEndpoint, false
	if insecure && s.allowInsecure && s.insecureEndpoint != "" {
		endpoint, isInsecure = s.insecureEndpoint, true
	}
	return Created{Token: tok, Endpoint: endpoint, ExpiresAt: time.Now().Add(webTTL), Insecure: isInsecure}, nil
}

// CreatePostgresSession authorizes userID to reach a postgres assetID as the
// given DB role and mints a bearer admission ticket (proto=postgres, no client
// key — a pgwire client cannot prove key possession, so the token is a bearer
// with the role bound in-claim, the same posture as web terminals). Mode="web"
// is reused as the no-cnf marker. Existence-hiding: unknown/non-postgres asset
// or an unentitled role both yield ErrNoAccess.
func (s *Service) CreatePostgresSession(ctx context.Context, userID, assetID uuid.UUID, role string) (Created, error) {
	roles, err := s.entitledPostgresLogins(ctx, userID, assetID)
	if err != nil {
		return Created{}, err
	}
	if !contains(roles, role) {
		return Created{}, ErrNoAccess
	}
	cfg, err := s.q.GetPostgresAssetConfig(ctx, assetID)
	if err != nil {
		return Created{}, err // asset is postgres (entitlement passed) so config exists
	}
	// ponytail: Mode="web" reused as the "no-cnf bearer" marker; rename to a
	// neutral "bearer" if a third bearer protocol appears.
	sid := uuid.New()
	tok, err := s.minter.Mint(sessiontoken.Claims{
		SessionID: sid, UserID: userID, AssetID: assetID,
		Protocol: "postgres", Mode: "web", Login: role, ClientKeyFingerprint: "",
	}, webTTL)
	if err != nil {
		return Created{}, err
	}
	return Created{Token: tok, Endpoint: s.gatewayEndpoint, ExpiresAt: time.Now().Add(webTTL), DefaultDatabase: cfg.DefaultDatabase}, nil
}

// CreateKubernetesSession authorizes userID to reach a k8s assetID and mints a
// bearer admission token carrying the user's materialized groups + the broker
// holding the cluster's tunnel. Existence-hiding: unknown/non-k8s asset or no
// entitled group both yield ErrNoAccess.
func (s *Service) CreateKubernetesSession(ctx context.Context, userID, assetID uuid.UUID) (Created, error) {
	a, err := s.q.GetAsset(ctx, assetID)
	if err != nil || a.Kind != "k8s" {
		return Created{}, ErrNoAccess
	}
	groups, err := authz.EntitledK8sGroups(ctx, s.authz, userID, assetID)
	if err != nil {
		return Created{}, err
	}
	if len(groups) == 0 {
		return Created{}, ErrNoAccess
	}
	brokerID, ok := s.brokers.BrokerForAsset(assetID.String())
	if !ok {
		return Created{}, ErrClusterOffline
	}
	sid := uuid.New()
	tok, err := s.minter.Mint(sessiontoken.Claims{
		SessionID: sid, UserID: userID, AssetID: assetID,
		Protocol: "kubernetes", Mode: "web",
		Groups: groups, BrokerID: brokerID,
	}, k8sTTL)
	if err != nil {
		return Created{}, err
	}
	return Created{Token: tok, Endpoint: s.gatewayEndpoint, ExpiresAt: time.Now().Add(k8sTTL)}, nil
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

// entitledPostgresLogins returns the caller's entitled DB roles on a postgres
// asset, or ErrNoAccess when none (unknown/non-postgres asset, or no db:login cap).
func (s *Service) entitledPostgresLogins(ctx context.Context, userID, assetID uuid.UUID) ([]string, error) {
	rows, err := s.q.ListPostgresAssetLogins(ctx, assetID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNoAccess
	}
	allowed := make([]string, 0, len(rows))
	for _, r := range rows {
		allowed = append(allowed, r.Role)
	}
	roles, err := authz.EntitledLoginsFor(ctx, s.authz, userID, assetID, authz.DBLoginPrefix, allowed)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, ErrNoAccess
	}
	return roles, nil
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
