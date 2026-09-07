package dataplane_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// spyBroker is a credential issuer that records how many times Issue was called
// WITHOUT minting anything real. It substitutes for *vault.Broker so the boundary
// test can prove the broker is untouched by preparation and by any mismatch — the
// central security invariant of the two-phase flow. It is a real behavioral spy,
// not a mock that asserts on call arguments: the test asserts on observable
// outcomes (call count, issued credential) only.
type spyBroker struct {
	calls atomic.Int64
	kind  string
}

func (b *spyBroker) Issue(_ context.Context, _, _ uuid.UUID, _ vault.IssueRequest) (vault.Credential, error) {
	b.calls.Add(1)
	return vault.Credential{Kind: b.kind, SSHCertificate: []byte("spy-cert")}, nil
}

func (b *spyBroker) IssueCalls() int64 { return b.calls.Load() }

// boundaryEnv wires a SetupService over a spy broker and a REAL target-identity
// service against a seeded ssh asset that carries one current active exact
// ssh_host_key anchor.
type boundaryEnv struct {
	*fixture
	broker   *spyBroker
	svc      *dataplane.SetupService
	anchor   uuid.UUID
	fp       string // the anchor's exact fingerprint (a correct observation matches it)
	rev      int64  // the asset's current endpoint revision
	workerID string
}

const boundaryWorkerID = "worker-boundary"

// newBoundaryEnv seeds a full fixture (via setup) plus one exact ssh_host_key trust
// anchor at the asset's current endpoint revision, and builds a SetupService whose
// broker is a spy and whose identity service is real.
func newBoundaryEnv(t *testing.T) *boundaryEnv {
	t.Helper()
	f := setup(t)
	broker := &spyBroker{kind: "ssh-cert"}
	identity := targetidentity.NewService(f.pool, audit.New(f.pool))
	svc := dataplane.NewSetupService(f.pool, f.verifier, authz.New(f.pool), broker, identity, audit.New(f.pool), time.Hour)

	asset, err := f.q.GetAsset(f.ctx, f.asset)
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	const fp = "SHA256:correct-observed-fingerprint"
	row, err := f.q.ApproveTrustAnchor(f.ctx, sqlc.ApproveTrustAnchorParams{
		AssetID:               f.asset,
		EndpointRevision:      asset.EndpointRevision,
		Kind:                  string(targetidentity.AnchorSSHHostKey),
		Algorithm:             "ssh-ed25519",
		Sha256Fingerprint:     fp,
		PublicMaterial:        "ssh-ed25519 AAAA...",
		RequiredSshPrincipals: []string{},
		RequiredDnsNames:      []string{},
		RequiredIpAddresses:   []string{},
		Source:                string(targetidentity.TrustSourceManual),
		ApprovedAt:            pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
	})
	if err != nil {
		t.Fatalf("ApproveTrustAnchor: %v", err)
	}
	return &boundaryEnv{fixture: f, broker: broker, svc: svc, anchor: row.ID, fp: fp, rev: asset.EndpointRevision, workerID: boundaryWorkerID}
}

// prepareSession redeems a token via the credential-free first phase.
func (e *boundaryEnv) prepareSession(t *testing.T, token string) dataplane.PrepareResult {
	t.Helper()
	prep, err := e.svc.Prepare(e.ctx, token, e.workerID, "deploy", e.clientPub)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return prep
}

// issue drives the second phase with the given observed fingerprint from the given
// worker, returning the result and error.
func (e *boundaryEnv) issue(sessionID, workerID string, rev int64, anchorID, observedFP string) (dataplane.IssueResult, error) {
	return e.svc.IssueCredential(e.ctx, sessionID, workerID, rev, anchorID, observedFP, e.workerPub)
}

// TestCredentialBoundaryPrepareNeverIssues is the central invariant: preparing a
// session must not touch the broker, and reporting a mismatched target identity
// must not either.
func TestCredentialBoundaryPrepareNeverIssues(t *testing.T) {
	e := newBoundaryEnv(t)
	token := e.mintToken(t, e.clientFp)

	prep := e.prepareSession(t, token)
	if e.broker.IssueCalls() != 0 {
		t.Fatal("credential issued during prepare")
	}
	// The prepared session exposes the endpoint + the anchor, but nothing secret.
	if prep.EndpointRevision != e.rev {
		t.Fatalf("EndpointRevision = %d, want %d", prep.EndpointRevision, e.rev)
	}
	if len(prep.Anchors) != 1 || prep.Anchors[0].ID != e.anchor {
		t.Fatalf("Anchors = %+v, want the seeded anchor %s", prep.Anchors, e.anchor)
	}

	// A wrong observed fingerprint is a mismatch → refused, broker still untouched.
	if _, err := e.issue(prep.SessionID, e.workerID, e.rev, e.anchor.String(), "SHA256:wrong"); err == nil {
		t.Fatal("issue with wrong fingerprint must fail")
	}
	if e.broker.IssueCalls() != 0 {
		t.Fatal("credential issued for mismatch")
	}
	// Cleanup: a failed issue tears down the prepared live session.
	if n := e.liveSessionCount(t); n != 0 {
		t.Fatalf("live_sessions rows = %d after mismatch, want 0 (aborted)", n)
	}
}

// TestCredentialBoundaryExactMatchIssuesOnce asserts a correct observation against
// the current anchor releases exactly one credential.
func TestCredentialBoundaryExactMatchIssuesOnce(t *testing.T) {
	e := newBoundaryEnv(t)
	token := e.mintToken(t, e.clientFp)
	prep := e.prepareSession(t, token)

	res, err := e.issue(prep.SessionID, e.workerID, e.rev, e.anchor.String(), e.fp)
	if err != nil {
		t.Fatalf("issue on exact match: %v", err)
	}
	if res.CredentialKind != "ssh-cert" || len(res.SSHCertificate) == 0 {
		t.Fatalf("unexpected credential %+v", res)
	}
	if e.broker.IssueCalls() != 1 {
		t.Fatalf("IssueCalls = %d, want exactly 1", e.broker.IssueCalls())
	}
}

// TestCredentialBoundaryStaleRevisionRejected asserts an issue against a revision
// that no longer matches the asset's current revision is refused without issuing.
func TestCredentialBoundaryStaleRevisionRejected(t *testing.T) {
	e := newBoundaryEnv(t)
	token := e.mintToken(t, e.clientFp)
	prep := e.prepareSession(t, token)

	if _, err := e.issue(prep.SessionID, e.workerID, e.rev+1, e.anchor.String(), e.fp); err == nil {
		t.Fatal("issue against a stale revision must fail")
	}
	if e.broker.IssueCalls() != 0 {
		t.Fatal("credential issued for a stale revision")
	}
}

// TestCredentialBoundaryWrongWorkerRejected asserts only the worker that prepared
// the session may issue its credential; a different worker is refused and the
// session is NOT torn down (ownership is checked before any cleanup).
func TestCredentialBoundaryWrongWorkerRejected(t *testing.T) {
	e := newBoundaryEnv(t)
	token := e.mintToken(t, e.clientFp)
	prep := e.prepareSession(t, token)

	if _, err := e.issue(prep.SessionID, "worker-other", e.rev, e.anchor.String(), e.fp); err == nil {
		t.Fatal("issue from a non-owning worker must fail")
	}
	if e.broker.IssueCalls() != 0 {
		t.Fatal("credential issued for the wrong worker")
	}
	if n := e.liveSessionCount(t); n != 1 {
		t.Fatalf("live_sessions rows = %d, want 1 (wrong-worker must not abort the session)", n)
	}
}

// TestCredentialBoundaryRevokedAnchorRejected asserts an issue naming an anchor
// that has been revoked (no longer a current active anchor) is refused without
// issuing.
func TestCredentialBoundaryRevokedAnchorRejected(t *testing.T) {
	e := newBoundaryEnv(t)
	token := e.mintToken(t, e.clientFp)
	prep := e.prepareSession(t, token)

	if _, err := e.q.RevokeTrustAnchor(e.ctx, sqlc.RevokeTrustAnchorParams{
		RevokedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		AnchorID:  e.anchor,
		AssetID:   e.asset,
	}); err != nil {
		t.Fatalf("RevokeTrustAnchor: %v", err)
	}
	if _, err := e.issue(prep.SessionID, e.workerID, e.rev, e.anchor.String(), e.fp); err == nil {
		t.Fatal("issue against a revoked anchor must fail")
	}
	if e.broker.IssueCalls() != 0 {
		t.Fatal("credential issued for a revoked anchor")
	}
}

// TestCredentialBoundaryDuplicateIssueReverifiesAndReMints asserts the real
// behavior of a repeat issue from the SAME owning worker: the session id is NOT a
// mint dedup key (it is only the broker's audit KeyID), so every call re-runs the
// full ownership + identity gate and mints again. Two successful calls therefore
// reach the broker twice (IssueCalls == 2) — for minted kinds that is a re-verified
// re-mint, not "exactly once" — while both return the same credential kind/session/
// login. This proves the intended behavior instead of green-lighting a silent
// double-mint the way a kind-only assertion would.
func TestCredentialBoundaryDuplicateIssueReverifiesAndReMints(t *testing.T) {
	e := newBoundaryEnv(t)
	token := e.mintToken(t, e.clientFp)
	prep := e.prepareSession(t, token)

	first, err := e.issue(prep.SessionID, e.workerID, e.rev, e.anchor.String(), e.fp)
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	second, err := e.issue(prep.SessionID, e.workerID, e.rev, e.anchor.String(), e.fp)
	if err != nil {
		t.Fatalf("duplicate issue: %v", err)
	}
	// The gate re-ran and the broker minted on BOTH calls — not deduplicated.
	if e.broker.IssueCalls() != 2 {
		t.Fatalf("IssueCalls = %d, want 2 (each call re-verifies and re-mints)", e.broker.IssueCalls())
	}
	if first.CredentialKind != second.CredentialKind || first.SessionID != second.SessionID {
		t.Fatalf("duplicate issue diverged: %+v vs %+v", first, second)
	}
	if first.Login != "deploy" || second.Login != "deploy" {
		t.Fatalf("login not carried through re-mint: %q / %q", first.Login, second.Login)
	}
}
