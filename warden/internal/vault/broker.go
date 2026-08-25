// Package vault implements the CredentialBroker: the single boundary that mints
// short-lived credentials for a user to reach an asset, driven by the user's
// live entitlements.
//
// SECURITY: the broker is the enforcement point for "which account may this
// user log into". Issue takes the requested login and enforces the
// ssh:login:<login> capability for EVERY auth kind (ca / password / key): the
// login must survive the intersection of the asset's configured logins with the
// user's actual capabilities, else the request is refused (no credential, no
// audit). For the ca kind it signs a certificate whose ValidPrincipals are
// host-scoped [login@<asset-path>, login@<asset-id>]; for password/key it opens
// the login's asset-scoped stored secret (a secret bound to another asset cannot
// be opened).
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
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
	// ErrNoLoginEntitlement is returned when the requested login is not a
	// configured login on the asset, or the user holds no ssh:login:<login>
	// capability for it.
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
	// Login is the requested target login. The broker enforces ssh:login:<Login>
	// for the caller (all kinds) and selects the login's configured auth kind.
	Login string
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
	Kind string // "ssh-cert" | "ssh-password" | "ssh-key" | "x509"

	SSHCertificate []byte // Kind == "ssh-cert": OpenSSH authorized_keys cert line

	X509Cert []byte // Kind == "x509": leaf certificate PEM
	X509Key  []byte // Kind == "x509": client private key PEM

	// Secret carries the plaintext stored secret for the password/key kinds:
	// Kind == "ssh-password" → the target password bytes; Kind == "ssh-key" →
	// the OpenSSH private key PEM bytes.
	Secret []byte
}

// Broker mints credentials for (user, asset) pairs.
type Broker struct {
	q      *sqlc.Queries
	sealer *secrets.Sealer
	authz  authz.Authorizer
	audit  *audit.Logger
}

// NewBroker constructs a Broker. A nil sealer disables the vault: Issue returns
// ErrVaultNotConfigured (fail closed).
func NewBroker(pool *pgxpool.Pool, sealer *secrets.Sealer, authorizer authz.Authorizer, auditLog *audit.Logger) *Broker {
	return &Broker{
		q:      sqlc.New(pool),
		sealer: sealer,
		authz:  authorizer,
		audit:  auditLog,
	}
}

// Issue mints a single credential for userID to reach assetID as the requested
// login. The credential shape is determined by the asset's kind and the login's
// configured auth kind. See the package doc for the security invariants
// (ssh:login:<login> enforced for every kind).
func (b *Broker) Issue(ctx context.Context, userID, assetID uuid.UUID, req IssueRequest) (Credential, error) {
	// Fail closed when the vault is disabled.
	if b.sealer == nil {
		return Credential{}, ErrVaultNotConfigured
	}

	asset, err := b.q.GetAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Credential{}, ErrNoConfig
		}
		return Credential{}, fmt.Errorf("get asset: %w", err)
	}

	switch asset.Kind {
	case "ssh":
		return b.issueSSH(ctx, userID, asset, req)
	default:
		// postgres / k8s providers land in M5.
		return Credential{}, ErrUnsupportedKind
	}
}

// issueSSH selects the requested login among the asset's login rows, enforces
// the ssh:login:<login> entitlement (for every kind), and mints the credential
// for that login's configured kind: a host-scoped cert (ca), or the plain
// stored password/key secret.
func (b *Broker) issueSSH(ctx context.Context, userID uuid.UUID, asset sqlc.Asset, req IssueRequest) (Credential, error) {
	assetID := asset.ID
	rows, err := b.q.ListSSHAssetLogins(ctx, assetID)
	if err != nil {
		return Credential{}, fmt.Errorf("list ssh asset logins: %w", err)
	}

	var row sqlc.SshAssetLogin
	found := false
	allLogins := make([]string, 0, len(rows))
	for _, r := range rows {
		allLogins = append(allLogins, r.Login)
		if r.Login == req.Login {
			row = r
			found = true
		}
	}
	if !found {
		return Credential{}, ErrNoLoginEntitlement
	}

	// Enforce the login entitlement uniformly for every kind: the requested login
	// must survive the intersection with the user's ssh:login:<login> caps.
	entitled, err := authz.EntitledLogins(ctx, b.authz, userID, assetID, allLogins)
	if err != nil {
		return Credential{}, err
	}
	if !contains(entitled, req.Login) {
		return Credential{}, ErrNoLoginEntitlement
	}

	switch row.Kind {
	case "ca":
		return b.issueSSHCert(ctx, userID, asset, req)
	case "password":
		return b.issueStoredSecret(ctx, userID, assetID, row, "ssh-password")
	case "key":
		return b.issueStoredSecret(ctx, userID, assetID, row, "ssh-key")
	default:
		return Credential{}, ErrUnsupportedKind
	}
}

// contains reports whether xs contains s.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// issueStoredSecret opens the login's asset-scoped stored secret and returns it
// as the given credential kind ("ssh-password" or "ssh-key"). The GetAssetSecret
// query is asset-scoped, so a secret belonging to another asset cannot be opened.
func (b *Broker) issueStoredSecret(ctx context.Context, userID, assetID uuid.UUID, row sqlc.SshAssetLogin, kind string) (Credential, error) {
	if !row.SecretID.Valid {
		// The ssh_login_secret_present CHECK makes this unreachable, but guard
		// anyway rather than pass a zero uuid.
		return Credential{}, ErrNoConfig
	}
	sec, err := b.q.GetAssetSecret(ctx, sqlc.GetAssetSecretParams{
		ID:      uuid.UUID(row.SecretID.Bytes),
		AssetID: assetID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Credential{}, ErrNoConfig
		}
		return Credential{}, fmt.Errorf("get asset secret: %w", err)
	}
	pt, err := b.sealer.Open(sec.Sealed)
	if err != nil {
		return Credential{}, fmt.Errorf("open asset secret: %w", err)
	}
	b.appendIssued(ctx, userID, assetID, map[string]any{
		"provider": "stored-secret",
		"kind":     kind,
		"login":    row.Login,
	})
	return Credential{Kind: kind, Secret: pt}, nil
}

// issueSSHCert signs the client's public key with host-scoped principals
// [login@<asset-path>, login@<asset-id>] and returns an "ssh-cert" credential.
func (b *Broker) issueSSHCert(ctx context.Context, userID uuid.UUID, asset sqlc.Asset, req IssueRequest) (Credential, error) {
	assetID := asset.ID
	caRow, err := b.q.GetActiveCA(ctx, "ssh")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Credential{}, ErrNoCA
		}
		return Credential{}, fmt.Errorf("get active ssh CA: %w", err)
	}
	seed, err := b.sealer.Open(caRow.Sealed)
	if err != nil {
		return Credential{}, fmt.Errorf("open ssh CA seed: %w", err)
	}
	sshCA, err := ca.LoadSSHCA(seed)
	if err != nil {
		return Credential{}, fmt.Errorf("load ssh CA: %w", err)
	}

	pub, err := parseSSHPublicKey(req.ClientSSHPubKey)
	if err != nil {
		return Credential{}, fmt.Errorf("parse client ssh public key: %w", err)
	}

	// FolderPath returns the folder's own dotted path (COALESCE'd to "" for a
	// root-level folder, never an error for a valid folder_id). asset.FolderID is
	// a NOT NULL FK, so an error here means a real DB failure — fail closed.
	folderPath, err := b.q.FolderPath(ctx, asset.FolderID)
	if err != nil {
		return Credential{}, fmt.Errorf("resolve asset path: %w", err)
	}
	assetPath := asset.Name
	if folderPath != "" {
		assetPath += "." + folderPath
	}

	principals := []string{
		req.Login + "@" + assetPath,
		req.Login + "@" + assetID.String(),
	}
	cert, err := sshCA.SignUserKey(pub, ca.SSHCertParams{
		KeyID:       req.KeyID,
		Principals:  principals,
		ValidBefore: req.ValidUntil,
	})
	if err != nil {
		return Credential{}, fmt.Errorf("sign user key: %w", err)
	}

	b.appendIssued(ctx, userID, assetID, map[string]any{
		"provider":    "ssh-ca",
		"kind":        "ca",
		"login":       req.Login,
		"principals":  principals,
		"key_id":      req.KeyID,
		"valid_until": req.ValidUntil.UTC().Format(time.RFC3339),
	})
	return Credential{Kind: "ssh-cert", SSHCertificate: ca.MarshalCert(cert)}, nil
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
