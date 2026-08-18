// Package vault implements the CredentialBroker: the single boundary that mints
// short-lived credentials for a user to reach an asset, driven by the user's
// live entitlements.
//
// SECURITY: the broker is the enforcement point for "which accounts may this
// user log into". For the SSH ca-cert path it does NOT trust the asset's
// allowed_logins list wholesale — it intersects that list with the user's
// actual capabilities (Authorizer.Check for "ssh:login:<login>") and signs a
// certificate whose ValidPrincipals is EXACTLY that intersection. An empty
// intersection is refused (no cert, no audit) rather than defaulting to an
// all-accounts cert. The ca layer independently refuses to sign a
// principal-less certificate as defense-in-depth.
//
// FAIL-CLOSED: a disabled vault (nil sealer), a missing CA, a missing config,
// or an unsupported asset kind all return a sentinel error and issue nothing.
//
// AUDIT: the credential.issued event is appended AFTER a successful issuance
// (mirroring accessrequest's post-fact audit pattern). An audit-append failure
// is logged loudly via slog but does not fail the issuance — the credential was
// already minted and returning an error would falsely report failure. A denied
// or errored issuance emits no audit event.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// Sentinel errors returned by Issue.
var (
	// ErrVaultNotConfigured is returned when the vault is disabled (no master
	// key / nil sealer). The broker fails closed rather than issuing anything.
	ErrVaultNotConfigured = errors.New("vault not configured")
	// ErrNoCA is returned when no active credential authority exists for the
	// requested kind (GetActiveCA found no row).
	ErrNoCA = errors.New("credential authority not initialized")
	// ErrNoLoginEntitlement is returned when the user holds no ssh:login:*
	// capability matching any of the asset's allowed logins.
	ErrNoLoginEntitlement = errors.New("no login entitlement on asset")
	// ErrUnsupportedKind is returned for an asset kind that has no credential
	// provider yet.
	ErrUnsupportedKind = errors.New("asset kind has no credential provider")
	// ErrNoConfig is returned when an asset has no credential config row.
	ErrNoConfig = errors.New("asset has no credential config")
)

// IssueRequest carries the caller-supplied inputs to Issue.
type IssueRequest struct {
	// ClientSSHPubKey is the client's ephemeral SSH public key to sign on the
	// ca-cert path. Accepted in OpenSSH authorized_keys text form
	// (ssh.MarshalAuthorizedKey) or raw wire form (ssh.PublicKey.Marshal); Issue
	// tries the authorized_keys parse first, then the wire parse.
	ClientSSHPubKey []byte
	// ValidUntil bounds the credential's lifetime. M4 passes the granting
	// access_grant's remaining TTL so a credential never outlives its grant.
	ValidUntil time.Time
	// KeyID is an audit handle stamped into the SSH cert's KeyId (e.g. grant id
	// or user id).
	KeyID string
}

// Credential is a single issued credential. Exactly one shape is populated per
// Credential value, discriminated by Kind.
type Credential struct {
	Kind string // "ssh-cert" | "x509" | "secret"

	SSHCertificate []byte // Kind == "ssh-cert": OpenSSH authorized_keys cert line

	X509Cert []byte // Kind == "x509": leaf certificate PEM
	X509Key  []byte // Kind == "x509": client private key PEM

	Secret []byte // Kind == "secret": raw stored secret plaintext
}

// Broker mints credentials for (user, asset) pairs.
type Broker struct {
	q      *gen.Queries
	sealer *secrets.Sealer
	authz  authz.Authorizer
	audit  *audit.Logger
}

// NewBroker constructs a Broker. A nil sealer disables the vault: Issue returns
// ErrVaultNotConfigured (fail closed).
func NewBroker(pool *pgxpool.Pool, sealer *secrets.Sealer, authorizer authz.Authorizer, auditLog *audit.Logger) *Broker {
	return &Broker{
		q:      gen.New(pool),
		sealer: sealer,
		authz:  authorizer,
		audit:  auditLog,
	}
}

// Issue mints credentials for userID to reach assetID. The credential shape is
// determined by the asset's kind and config. See the package doc for the
// security invariants (principal = allowed_logins ∩ user capabilities).
func (b *Broker) Issue(ctx context.Context, userID, assetID uuid.UUID, req IssueRequest) ([]Credential, error) {
	// Fail closed when the vault is disabled.
	if b.sealer == nil {
		return nil, ErrVaultNotConfigured
	}

	asset, err := b.q.GetAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoConfig
		}
		return nil, fmt.Errorf("get asset: %w", err)
	}

	switch asset.Kind {
	case "ssh":
		return b.issueSSH(ctx, userID, assetID, req)
	default:
		// postgres / k8s providers land in M5.
		return nil, ErrUnsupportedKind
	}
}

// issueSSH handles the ssh asset kind: either a stored key (auth_method
// 'stored-key') or a signed short-lived user certificate (auth_method
// 'ca-cert').
func (b *Broker) issueSSH(ctx context.Context, userID, assetID uuid.UUID, req IssueRequest) ([]Credential, error) {
	cfg, err := b.q.GetSSHAssetConfig(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoConfig
		}
		return nil, fmt.Errorf("get ssh asset config: %w", err)
	}

	if cfg.AuthMethod == "stored-key" {
		return b.issueStoredSecret(ctx, userID, assetID, cfg)
	}
	return b.issueSSHCert(ctx, userID, assetID, cfg, req)
}

// issueStoredSecret opens the asset's stored secret and returns it as a
// "secret" credential.
func (b *Broker) issueStoredSecret(ctx context.Context, userID, assetID uuid.UUID, cfg gen.SshAssetConfig) ([]Credential, error) {
	if !cfg.StoredSecretID.Valid {
		// The stored_key_needs_secret CHECK constraint makes this unreachable,
		// but guard anyway rather than pass a zero uuid.
		return nil, ErrNoConfig
	}
	row, err := b.q.GetAssetSecret(ctx, gen.GetAssetSecretParams{
		ID:      uuid.UUID(cfg.StoredSecretID.Bytes),
		AssetID: assetID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoConfig
		}
		return nil, fmt.Errorf("get asset secret: %w", err)
	}
	pt, err := b.sealer.Open(row.Sealed)
	if err != nil {
		return nil, fmt.Errorf("open asset secret: %w", err)
	}
	creds := []Credential{{Kind: "secret", Secret: pt}}
	b.appendIssued(ctx, userID, assetID, map[string]any{
		"provider":    "stored-secret",
		"secret_name": row.Name,
	})
	return creds, nil
}

// issueSSHCert derives the entitled principals, signs the client's public key,
// and returns an "ssh-cert" credential. The principals are the intersection of
// the asset's allowed_logins and the user's ssh:login:<login> capabilities.
func (b *Broker) issueSSHCert(ctx context.Context, userID, assetID uuid.UUID, cfg gen.SshAssetConfig, req IssueRequest) ([]Credential, error) {
	var principals []string
	for _, login := range cfg.AllowedLogins {
		ok, err := b.authz.Check(ctx, userID, assetID, "ssh:login:"+login)
		if err != nil {
			return nil, err
		}
		if ok {
			principals = append(principals, login)
		}
	}
	if len(principals) == 0 {
		return nil, ErrNoLoginEntitlement
	}

	caRow, err := b.q.GetActiveCA(ctx, "ssh")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoCA
		}
		return nil, fmt.Errorf("get active ssh CA: %w", err)
	}
	seed, err := b.sealer.Open(caRow.Sealed)
	if err != nil {
		return nil, fmt.Errorf("open ssh CA seed: %w", err)
	}
	sshCA, err := ca.LoadSSHCA(seed)
	if err != nil {
		return nil, fmt.Errorf("load ssh CA: %w", err)
	}

	pub, err := parseSSHPublicKey(req.ClientSSHPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse client ssh public key: %w", err)
	}

	cert, err := sshCA.SignUserKey(pub, ca.SSHCertParams{
		KeyID:       req.KeyID,
		Principals:  principals,
		ValidBefore: req.ValidUntil,
	})
	if err != nil {
		return nil, fmt.Errorf("sign user key: %w", err)
	}

	creds := []Credential{{Kind: "ssh-cert", SSHCertificate: ca.MarshalCert(cert)}}
	b.appendIssued(ctx, userID, assetID, map[string]any{
		"provider":    "ssh-ca",
		"principals":  principals,
		"key_id":      req.KeyID,
		"valid_until": req.ValidUntil.UTC().Format(time.RFC3339),
	})
	return creds, nil
}

// parseSSHPublicKey accepts the client public key in either OpenSSH
// authorized_keys text form or raw SSH wire form. It tries the authorized_keys
// parse first (what ssh.MarshalAuthorizedKey produces) and falls back to the
// wire parse (what ssh.PublicKey.Marshal produces).
func parseSSHPublicKey(raw []byte) (ssh.PublicKey, error) {
	if pub, _, _, _, err := ssh.ParseAuthorizedKey(raw); err == nil {
		return pub, nil
	}
	pub, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// appendIssued writes the credential.issued audit event (best-effort). The
// credential was already minted; a failed append is logged loudly (a hole in
// the tamper-evident trail) but does not fail the issuance.
func (b *Broker) appendIssued(ctx context.Context, userID, assetID uuid.UUID, details map[string]any) {
	if b.audit == nil {
		return
	}
	raw, _ := json.Marshal(details)
	if err := b.audit.Append(ctx, audit.Event{
		Type:    EventCredentialIssued,
		ActorID: userID,
		Subject: "asset:" + assetID.String(),
		Details: raw,
	}); err != nil {
		slog.Error("audit append failed", "event", EventCredentialIssued, "asset_id", assetID.String(), "err", err)
	}
}
