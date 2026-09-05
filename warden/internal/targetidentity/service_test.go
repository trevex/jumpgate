package targetidentity_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

func TestVerificationStateTransitions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *targetIdentityEnv)
	}{
		{
			name: "pending to awaiting approval to verified",
			run: func(t *testing.T, env *targetIdentityEnv) {
				if got := env.status(t); got != targetidentity.StatusPendingVerification {
					t.Fatalf("initial status = %q; want pending_verification", got)
				}
				if got := env.complete(t, sshEvidence("old")); got != targetidentity.StatusAwaitingApproval {
					t.Fatalf("post-probe status = %q; want awaiting_approval", got)
				}
				evidence := env.evidence(t)
				env.approve(t, evidence[0].ObservationID, evidence[0].Fingerprint, time.Time{})
				if got := env.status(t); got != targetidentity.StatusVerified {
					t.Fatalf("approved status = %q; want verified", got)
				}
			},
		},
		{
			name: "failed probe can be manually retried",
			run: func(t *testing.T, env *targetIdentityEnv) {
				job := env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
				if got := env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionTimeout); got != targetidentity.StatusProbeFailed {
					t.Fatalf("failed status = %q; want probe_failed", got)
				}
				retry := env.queue(t, targetidentity.ProbeReasonManual, job.ID)
				if retry.PreviousJobID != job.ID {
					t.Fatalf("retry previous job = %s; want %s", retry.PreviousJobID, job.ID)
				}
				if got := env.claimAndComplete(t, targetidentity.ProbeSucceeded, "", sshEvidence("retry")); got != targetidentity.StatusAwaitingApproval {
					t.Fatalf("retry status = %q; want awaiting_approval", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.run(t, newTargetIdentityEnv(t)) })
	}
}

func TestApproveRejectsStaleRevisionAndFingerprint(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.complete(t, sshEvidence("old"))
	evidence := env.evidence(t)[0]

	if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence.ObservationID,
		EvidenceID:          evidence.ID,
		SelectedFingerprint: fingerprint("not-observed"), Source: targetidentity.TrustSourceManual, ActorID: env.actor,
	}); !errors.Is(err, targetidentity.ErrEvidenceNotFound) {
		t.Fatalf("wrong fingerprint error = %v; want ErrEvidenceNotFound", err)
	}
	if _, err := env.q.IncrementAssetEndpointRevision(env.ctx, env.asset); err != nil {
		t.Fatalf("increment revision: %v", err)
	}
	if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence.ObservationID,
		EvidenceID:          evidence.ID,
		SelectedFingerprint: evidence.Fingerprint, Source: targetidentity.TrustSourceManual, ActorID: env.actor,
	}); !errors.Is(err, targetidentity.ErrStaleRevision) {
		t.Fatalf("stale approval error = %v; want ErrStaleRevision", err)
	}
}

func TestApprovalIsAdditiveAndRevocationPreservesOtherMatchingAnchor(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.complete(t, sshEvidence("blue"), sshEvidence("green"))
	evidence := env.evidence(t)
	if len(evidence) != 2 {
		t.Fatalf("evidence count = %d; want 2", len(evidence))
	}
	blue := env.approve(t, evidence[0].ObservationID, fingerprint("blue"), time.Time{})
	env.approve(t, evidence[0].ObservationID, fingerprint("green"), time.Time{})
	anchors, err := env.svc.ListAnchors(env.ctx, env.asset)
	if err != nil {
		t.Fatalf("list anchors: %v", err)
	}
	if len(anchors) != 2 {
		t.Fatalf("anchor count = %d; want 2", len(anchors))
	}
	if _, err := env.svc.RevokeAnchor(env.ctx, targetidentity.RevokeAnchorRequest{
		AssetID: env.asset, ExpectedRevision: 1, AnchorID: blue.ID, ActorID: env.actor, Reason: "rotation complete",
	}); err != nil {
		t.Fatalf("revoke anchor: %v", err)
	}
	if got := env.status(t); got != targetidentity.StatusVerified {
		t.Fatalf("status after one revocation = %q; want verified", got)
	}
}

func TestStatusFreshnessUsesServiceClock(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.complete(t, sshEvidence("freshness"))
	evidence := env.evidence(t)[0]
	env.approve(t, evidence.ObservationID, evidence.Fingerprint, time.Time{})
	future := time.Now().Add(2 * time.Hour)
	env.svc = targetidentity.NewService(testPool, audit.New(testPool), targetidentity.WithClock(func() time.Time { return future }))
	if got, err := env.svc.Status(env.ctx, targetidentity.StatusRequest{AssetID: env.asset, Freshness: time.Hour}); err != nil {
		t.Fatalf("expired freshness status: %v", err)
	} else if got != targetidentity.StatusVerificationExpired {
		t.Fatalf("status with injected future clock = %q; want verification_expired", got)
	}
	if got, err := env.svc.Status(env.ctx, targetidentity.StatusRequest{AssetID: env.asset, Freshness: 3 * time.Hour}); err != nil {
		t.Fatalf("valid freshness status: %v", err)
	} else if got != targetidentity.StatusVerified {
		t.Fatalf("status within injected-clock freshness = %q; want verified", got)
	}
}

func TestMatchingProbeDoesNotSilentlyResolveIdentityChanged(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.complete(t, sshEvidence("old"))
	evidence := env.evidence(t)[0]
	env.approve(t, evidence.ObservationID, evidence.Fingerprint, time.Time{})

	if _, err := env.svc.RecordSessionMismatch(env.ctx, targetidentity.SessionMismatchRequest{
		AssetID: env.asset, EndpointRevision: 1, WorkerID: env.worker,
		ResolvedAddresses: []string{"192.0.2.11"}, SSH: &targetidentity.SSHMetadata{Banner: "SSH-2.0-new"},
		Evidence: []targetidentity.Evidence{sshEvidence("new")},
	}); err != nil {
		t.Fatalf("record mismatch: %v", err)
	}
	env.queue(t, targetidentity.ProbeReasonManual, uuid.Nil)
	env.claimAndComplete(t, targetidentity.ProbeSucceeded, "", sshEvidence("old"))
	if got := env.status(t); got != targetidentity.StatusIdentityChanged {
		t.Fatalf("status = %q; want identity_changed", got)
	}
}

func TestExplicitRejectionResolvesIdentityChanged(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.complete(t, sshEvidence("old"))
	evidence := env.evidence(t)[0]
	env.approve(t, evidence.ObservationID, evidence.Fingerprint, time.Time{})

	if _, err := env.svc.RecordSessionMismatch(env.ctx, targetidentity.SessionMismatchRequest{
		AssetID: env.asset, EndpointRevision: 1, WorkerID: env.worker,
		Evidence: []targetidentity.Evidence{sshEvidence("noise")},
	}); err != nil {
		t.Fatalf("record mismatch: %v", err)
	}
	all := env.evidence(t)
	mismatchObservation := all[len(all)-1].ObservationID
	if got, err := env.svc.RejectObservation(env.ctx, targetidentity.RejectObservationRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: mismatchObservation,
		ActorID: env.actor, Reason: "known middlebox was removed",
	}); err != nil {
		t.Fatalf("reject observation: %v", err)
	} else if got != targetidentity.StatusVerified {
		t.Fatalf("resolved status = %q; want verified", got)
	}
}

func TestExplicitApprovalOfChangedIdentityResolvesAfterOldAnchorRevocation(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.complete(t, sshEvidence("old"))
	oldEvidence := env.evidence(t)[0]
	oldAnchor := env.approve(t, oldEvidence.ObservationID, oldEvidence.Fingerprint, time.Time{})
	if _, err := env.svc.RecordSessionMismatch(env.ctx, targetidentity.SessionMismatchRequest{
		AssetID: env.asset, EndpointRevision: 1, WorkerID: env.worker,
		Evidence: []targetidentity.Evidence{sshEvidence("new")},
	}); err != nil {
		t.Fatalf("record mismatch: %v", err)
	}
	if _, err := env.svc.RevokeAnchor(env.ctx, targetidentity.RevokeAnchorRequest{
		AssetID: env.asset, ExpectedRevision: 1, AnchorID: oldAnchor.ID, ActorID: env.actor, Reason: "replace compromised key",
	}); err != nil {
		t.Fatalf("revoke old anchor: %v", err)
	}
	var changed targetidentity.Evidence
	for _, item := range env.evidence(t) {
		if item.Fingerprint == fingerprint("new") {
			changed = item
		}
	}
	if changed.ID == uuid.Nil {
		t.Fatal("changed evidence was not persisted")
	}
	_, status, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: changed.ObservationID,
		EvidenceID:          changed.ID,
		SelectedFingerprint: changed.Fingerprint, Source: targetidentity.TrustSourceManual, ActorID: env.actor,
	})
	if err != nil {
		t.Fatalf("approve changed identity: %v", err)
	}
	if status != targetidentity.StatusVerified {
		t.Fatalf("status = %q; want verified", status)
	}
}

func TestValidationBoundsAndCanonicalFingerprint(t *testing.T) {
	env := newTargetIdentityEnv(t)
	tests := []struct {
		name string
		item targetidentity.Evidence
	}{
		{name: "noncanonical fingerprint", item: targetidentity.Evidence{Kind: targetidentity.EvidenceSSHHostKey, Algorithm: "ssh-ed25519", Fingerprint: "SHA256:not base64", PublicMaterial: "key"}},
		{name: "oversized material", item: targetidentity.Evidence{Kind: targetidentity.EvidenceSSHHostKey, Algorithm: "ssh-ed25519", Fingerprint: fingerprint("large"), PublicMaterial: string(make([]byte, targetidentity.MaxPublicMaterialBytes+1))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env.queue(t, targetidentity.ProbeReasonManual, uuid.Nil)
			lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			_, err = env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, Evidence: []targetidentity.Evidence{tt.item}}})
			if !errors.Is(err, targetidentity.ErrInvalidResult) {
				t.Fatalf("error = %v; want ErrInvalidResult", err)
			}
		})
	}
}

func TestMutationsAreTransactionallyAudited(t *testing.T) {
	env := newTargetIdentityEnv(t)
	before, err := env.q.CountOutbox(env.ctx)
	if err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	env.complete(t, sshEvidence("audited"))
	evidence := env.evidence(t)[0]
	env.approve(t, evidence.ObservationID, evidence.Fingerprint, time.Time{})
	after, err := env.q.CountOutbox(env.ctx)
	if err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if added := after - before; added < 5 {
		t.Fatalf("audit events added = %d; want at least queue, lease, completion, observation, approval", added)
	}
}

func TestClaimSkipsJobsForOtherProtocols(t *testing.T) {
	postgresEnv := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	postgresEnv.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	sshEnv := newTargetIdentityEnv(t)
	sshJob := sshEnv.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)

	lease, err := sshEnv.svc.Claim(sshEnv.ctx, targetidentity.ClaimRequest{WorkerID: sshEnv.worker, Protocol: targetidentity.ProtocolSSH})
	if err != nil {
		t.Fatalf("claim ssh probe behind postgres probe: %v", err)
	}
	if lease.JobID != sshJob.ID || lease.Endpoint.Protocol != targetidentity.ProtocolSSH {
		t.Fatalf("claimed job/protocol = %s/%q; want %s/ssh", lease.JobID, lease.Endpoint.Protocol, sshJob.ID)
	}
	postgresLease, err := postgresEnv.svc.Claim(postgresEnv.ctx, targetidentity.ClaimRequest{WorkerID: postgresEnv.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("consume postgres probe: %v", err)
	}
	if _, err := postgresEnv.svc.Complete(postgresEnv.ctx, targetidentity.CompleteRequest{
		JobID: postgresLease.JobID, WorkerID: postgresEnv.worker, LeaseToken: postgresLease.Token,
		Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeFailed, FailureCategory: targetidentity.FailureNoCompatibleWorker},
	}); err != nil {
		t.Fatalf("complete postgres probe: %v", err)
	}
}

func TestCompleteIsIdempotentForAnAlreadyCompletedLease(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	req := targetidentity.CompleteRequest{
		JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
		Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, Evidence: []targetidentity.Evidence{sshEvidence("once")}},
	}
	if _, err := env.svc.Complete(env.ctx, req); err != nil {
		t.Fatalf("first complete: %v", err)
	}
	beforeEvidence := len(env.evidence(t))
	beforeAudit, err := env.q.CountOutbox(env.ctx)
	if err != nil {
		t.Fatalf("count outbox before duplicate: %v", err)
	}
	if got, err := env.svc.Complete(env.ctx, req); err != nil {
		t.Fatalf("duplicate complete: %v", err)
	} else if got != targetidentity.StatusAwaitingApproval {
		t.Fatalf("duplicate status = %q; want awaiting_approval", got)
	}
	if got := len(env.evidence(t)); got != beforeEvidence {
		t.Fatalf("evidence after duplicate = %d; want %d", got, beforeEvidence)
	}
	afterAudit, err := env.q.CountOutbox(env.ctx)
	if err != nil {
		t.Fatalf("count outbox after duplicate: %v", err)
	}
	if afterAudit != beforeAudit {
		t.Fatalf("audit rows after duplicate = %d; want %d", afterAudit, beforeAudit)
	}
}

func TestCAApprovalUsesExplicitLeafValidationFactWithoutPresentedRoot(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	now := time.Now()
	leaf := targetidentity.Evidence{
		Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: fingerprint("leaf"),
		PublicMaterial: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
		DNSNames:       []string{"db.test"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim postgres probe: %v", err)
	}
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
		JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
		Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{ServerName: "db.test"}, Evidence: []targetidentity.Evidence{leaf}},
	}); err != nil {
		t.Fatalf("complete postgres probe: %v", err)
	}
	persistedLeaf := env.evidence(t)[0]
	rootMaterial, rootFingerprint := testCAPEM(t, "operator-root")
	if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: persistedLeaf.ObservationID,
		SelectedFingerprint: rootFingerprint, AnchorKind: targetidentity.AnchorTLSCA,
		SuppliedAlgorithm: "x509", SuppliedPublicMaterial: rootMaterial,
		RequiredDNSNames: []string{"db.test"}, Source: targetidentity.TrustSourceManual, ActorID: env.actor,
	}); !errors.Is(err, targetidentity.ErrValidationFactNeeded) {
		t.Fatalf("CA approval without fact error = %v; want ErrValidationFactNeeded", err)
	}
	anchor, status, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: persistedLeaf.ObservationID,
		SelectedFingerprint: rootFingerprint, AnchorKind: targetidentity.AnchorTLSCA,
		SuppliedAlgorithm: "x509", SuppliedPublicMaterial: rootMaterial,
		ValidatedEvidenceID: persistedLeaf.ID, RequiredDNSNames: []string{"db.test"},
		Source: targetidentity.TrustSourceManual, ActorID: env.actor,
	})
	if err != nil {
		t.Fatalf("approve unpresented CA: %v", err)
	}
	if status != targetidentity.StatusVerified {
		t.Fatalf("status = %q; want verified", status)
	}
	if anchor.Fingerprint != rootFingerprint || anchor.Kind != targetidentity.AnchorTLSCA {
		t.Fatalf("anchor = %#v; want unpresented TLS CA", anchor)
	}
	if got := len(env.evidence(t)); got != 1 {
		t.Fatalf("evidence count = %d; want only the presented leaf", got)
	}
}

func TestApprovalSelectsEvidenceByStableID(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	now := time.Now()
	sharedFingerprint := fingerprint("ambiguous")
	leaf := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: sharedFingerprint, PublicMaterial: "leaf", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	intermediate := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSIntermediate, Algorithm: "x509", Fingerprint: sharedFingerprint, PublicMaterial: "intermediate", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{ServerName: "db.test"}, Evidence: []targetidentity.Evidence{leaf, intermediate}}}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	var persistedLeaf targetidentity.Evidence
	for _, item := range env.evidence(t) {
		if item.Kind == targetidentity.EvidenceTLSLeaf {
			persistedLeaf = item
		}
	}
	anchor, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
		AssetID: env.asset, ExpectedRevision: 1, ObservationID: persistedLeaf.ObservationID,
		EvidenceID: persistedLeaf.ID, SelectedFingerprint: sharedFingerprint, AnchorKind: targetidentity.AnchorTLSLeaf,
		Source: targetidentity.TrustSourceManual, ActorID: env.actor,
	})
	if err != nil {
		t.Fatalf("approve exact evidence ID: %v", err)
	}
	if anchor.PublicMaterial != "leaf" || anchor.Kind != targetidentity.AnchorTLSLeaf {
		t.Fatalf("approved anchor = %#v; want selected TLS leaf", anchor)
	}
}

func TestValidationFactBindsKindAndFingerprint(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	now := time.Now()
	firstLeaf := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: fingerprint("first-leaf"), PublicMaterial: "first", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim first: %v", err)
	}
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{}, Evidence: []targetidentity.Evidence{firstLeaf}}}); err != nil {
		t.Fatalf("complete first: %v", err)
	}
	persistedLeaf := env.evidence(t)[0]
	rootMaterial, rootFingerprint := testCAPEM(t, "validation-root")
	anchor, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{AssetID: env.asset, ExpectedRevision: 1, ObservationID: persistedLeaf.ObservationID, SelectedFingerprint: rootFingerprint, AnchorKind: targetidentity.AnchorTLSCA, SuppliedPublicMaterial: rootMaterial, ValidatedEvidenceID: persistedLeaf.ID, Source: targetidentity.TrustSourceManual, ActorID: env.actor})
	if err != nil {
		t.Fatalf("approve CA: %v", err)
	}
	sharedFingerprint := fingerprint("second-leaf")
	secondLeaf := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: sharedFingerprint, PublicMaterial: "second", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	intermediate := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSIntermediate, Algorithm: "x509", Fingerprint: sharedFingerprint, PublicMaterial: "intermediate", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	env.queue(t, targetidentity.ProbeReasonManual, uuid.Nil)
	lease, err = env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim second: %v", err)
	}
	status, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{}, Evidence: []targetidentity.Evidence{secondLeaf, intermediate}, ValidationFacts: []targetidentity.ValidationFact{{AnchorID: anchor.ID, EvidenceKind: targetidentity.EvidenceTLSLeaf, EvidenceFingerprint: sharedFingerprint}}}})
	if err != nil {
		t.Fatalf("complete validated probe: %v", err)
	}
	if status != targetidentity.StatusVerified {
		t.Fatalf("status = %q; want verified", status)
	}
}

func TestCompleteRejectsProtocolIncompatibleSuccessfulResult(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	_, err = env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{}, Evidence: []targetidentity.Evidence{{Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: fingerprint("wrong-protocol"), PublicMaterial: "cert", ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}}}})
	if !errors.Is(err, targetidentity.ErrInvalidResult) {
		t.Fatalf("error = %v; want ErrInvalidResult", err)
	}
}

func TestCompleteRejectsProtocolIncompatibleFailedResult(t *testing.T) {
	tests := []struct {
		name   string
		result targetidentity.ProbeResult
	}{
		{
			name: "metadata",
			result: targetidentity.ProbeResult{
				Outcome:         targetidentity.ProbeFailed,
				FailureCategory: targetidentity.FailureProtocolMismatch,
				TLS:             &targetidentity.TLSMetadata{},
			},
		},
		{
			name: "evidence",
			result: targetidentity.ProbeResult{
				Outcome:         targetidentity.ProbeFailed,
				FailureCategory: targetidentity.FailureProtocolMismatch,
				Evidence: []targetidentity.Evidence{{
					Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509",
					Fingerprint: fingerprint("failed-wrong-protocol"), PublicMaterial: "cert",
					ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTargetIdentityEnv(t)
			env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
			lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			_, err = env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
				JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: tt.result,
			})
			if !errors.Is(err, targetidentity.ErrInvalidResult) {
				t.Fatalf("error = %v; want ErrInvalidResult", err)
			}
		})
	}
}

func TestCompleteAcceptsKubernetesMetadataAndTLSEvidence(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolKubernetes)
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolKubernetes})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	now := time.Now()
	status, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
		JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
		Result: targetidentity.ProbeResult{
			Outcome:    targetidentity.ProbeSucceeded,
			Kubernetes: &targetidentity.KubernetesMetadata{APIServerName: "kubernetes.default.svc"},
			Evidence: []targetidentity.Evidence{{
				Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509",
				Fingerprint: fingerprint("kubernetes-api"), PublicMaterial: "cert",
				DNSNames: []string{"kubernetes.default.svc"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
			}},
		},
	})
	if err != nil {
		t.Fatalf("complete Kubernetes probe: %v", err)
	}
	if status != targetidentity.StatusAwaitingApproval {
		t.Fatalf("status = %q; want awaiting_approval", status)
	}
}

func TestQueueProbeWrapsPreviousJobLookupFailure(t *testing.T) {
	env := newTargetIdentityEnv(t)
	if _, err := testPool.Exec(env.ctx, `ALTER TABLE target_probe_jobs RENAME TO target_probe_jobs_unavailable`); err != nil {
		t.Fatalf("hide probe jobs table: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `ALTER TABLE target_probe_jobs_unavailable RENAME TO target_probe_jobs`); err != nil {
			t.Errorf("restore probe jobs table: %v", err)
		}
	})
	_, err := env.svc.QueueProbe(env.ctx, targetidentity.QueueProbeRequest{
		AssetID: env.asset, EndpointRevision: 1, Reason: targetidentity.ProbeReasonManual,
		RequestedBy: env.actor, PreviousJobID: uuid.New(), MaxAttempts: 3,
	})
	if err == nil || errors.Is(err, targetidentity.ErrInvalidRequest) {
		t.Fatalf("error = %v; want wrapped operational error", err)
	}
	if !strings.Contains(err.Error(), "get previous probe job state") {
		t.Fatalf("error = %v; want previous-job lookup context", err)
	}
}

func TestStatusUsesOneInjectedTimeForAnchorAndCertificateValidity(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	base := time.Now().UTC()
	env.svc = targetidentity.NewService(testPool, audit.New(testPool), targetidentity.WithClock(func() time.Time { return base }))
	leaf := targetidentity.Evidence{
		Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509",
		Fingerprint: fingerprint("future-anchor"), PublicMaterial: "leaf",
		ValidFrom: base.Add(-time.Hour), ValidUntil: base.Add(2 * time.Hour),
	}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
		JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
		Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{}, Evidence: []targetidentity.Evidence{leaf}},
	}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	evidence := env.evidence(t)[0]
	activation := base.Add(time.Hour)
	if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence.ObservationID, EvidenceID: evidence.ID, SelectedFingerprint: evidence.Fingerprint, AnchorKind: targetidentity.AnchorTLSLeaf, Source: targetidentity.TrustSourceManual, ActorID: env.actor, NotBefore: activation}); err != nil {
		t.Fatalf("approve future anchor: %v", err)
	}
	checkAt := activation.Add(time.Minute)
	env.svc = targetidentity.NewService(testPool, audit.New(testPool), targetidentity.WithClock(func() time.Time { return checkAt }))
	if got := env.status(t); got != targetidentity.StatusVerified {
		t.Fatalf("status at injected activation time = %q; want verified", got)
	}
	checkAt = leaf.ValidUntil.Add(time.Minute)
	if got := env.status(t); got != targetidentity.StatusIdentityChanged {
		t.Fatalf("status after certificate expiry = %q; want identity_changed", got)
	}
}

func TestApproveRejectsIneligibleObservationAndCrossProtocolAnchor(t *testing.T) {
	env := newTargetIdentityEnv(t)
	job := env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	_ = job
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	failedEvidence := sshEvidence("failed")
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeFailed, FailureCategory: targetidentity.FailureProtocolMismatch, SSH: &targetidentity.SSHMetadata{}, Evidence: []targetidentity.Evidence{failedEvidence}}}); err != nil {
		t.Fatalf("complete failed probe: %v", err)
	}
	evidence := env.evidence(t)[0]
	if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence.ObservationID, EvidenceID: evidence.ID, SelectedFingerprint: evidence.Fingerprint, Source: targetidentity.TrustSourceManual, ActorID: env.actor}); !errors.Is(err, targetidentity.ErrInvalidRequest) {
		t.Fatalf("failed-observation approval error = %v; want ErrInvalidRequest", err)
	}
	env.queue(t, targetidentity.ProbeReasonManual, uuid.Nil)
	env.claimAndComplete(t, targetidentity.ProbeSucceeded, "", sshEvidence("eligible"))
	for _, item := range env.evidence(t) {
		if item.Fingerprint == fingerprint("eligible") {
			evidence = item
			break
		}
	}
	caMaterial, caFingerprint := testCAPEM(t, "wrong-kind")
	if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence.ObservationID, SelectedFingerprint: caFingerprint, AnchorKind: targetidentity.AnchorTLSCA, SuppliedPublicMaterial: caMaterial, ValidatedEvidenceID: evidence.ID, Source: targetidentity.TrustSourceManual, ActorID: env.actor}); !errors.Is(err, targetidentity.ErrUnsupportedEvidence) {
		t.Fatalf("cross-protocol approval error = %v; want ErrUnsupportedEvidence", err)
	}
}

func TestEvidenceRejectsUnboundedCertificateFields(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	bad := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: fingerprint("bad-fields"), PublicMaterial: "cert", CertificateSubject: string(make([]byte, targetidentity.MaxCertificateNameBytes+1)), ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	_, err = env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{}, Evidence: []targetidentity.Evidence{bad}}})
	if !errors.Is(err, targetidentity.ErrInvalidResult) {
		t.Fatalf("error = %v; want ErrInvalidResult", err)
	}
}

func TestSuppliedCAFingerprintIsDerivedFromMaterial(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	now := time.Now()
	leaf := targetidentity.Evidence{Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: fingerprint("derive-leaf"), PublicMaterial: "leaf", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token, Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{}, Evidence: []targetidentity.Evidence{leaf}}}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	persisted := env.evidence(t)[0]
	material, derived := testCAPEM(t, "derived")
	anchor, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{AssetID: env.asset, ExpectedRevision: 1, ObservationID: persisted.ObservationID, SelectedFingerprint: fingerprint("caller-lie"), AnchorKind: targetidentity.AnchorTLSCA, SuppliedPublicMaterial: material, ValidatedEvidenceID: persisted.ID, Source: targetidentity.TrustSourceManual, ActorID: env.actor})
	if err != nil {
		t.Fatalf("approve supplied CA: %v", err)
	}
	if anchor.Fingerprint != derived {
		t.Fatalf("fingerprint = %q; want derived %q", anchor.Fingerprint, derived)
	}
}

func TestAuditFailureRollsBackDomainMutation(t *testing.T) {
	env := newTargetIdentityEnv(t)
	env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
	_, err := env.svc.QueueProbe(env.ctx, targetidentity.QueueProbeRequest{
		AssetID: env.asset, EndpointRevision: 1, Reason: targetidentity.ProbeReasonOnboarding,
		RequestedBy: env.actor, MaxAttempts: 3,
	})
	if !errors.Is(err, errAuditRejected) {
		t.Fatalf("queue error = %v; want audit rejection", err)
	}
	var jobs int
	if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_probe_jobs WHERE asset_id=$1`, env.asset).Scan(&jobs); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobs != 0 {
		t.Fatalf("jobs after audit failure = %d; want 0", jobs)
	}
}

func TestAuditFailureRollsBackEachDistinctMutationTransaction(t *testing.T) {
	t.Run("claim", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		job := env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
		env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
		if _, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH}); !errors.Is(err, errAuditRejected) {
			t.Fatalf("claim error = %v; want audit rejection", err)
		}
		var state string
		var attempts int
		if err := testPool.QueryRow(env.ctx, `SELECT state,attempt_count FROM target_probe_jobs WHERE id=$1`, job.ID).Scan(&state, &attempts); err != nil {
			t.Fatalf("read rolled-back claim: %v", err)
		}
		if state != "queued" || attempts != 0 {
			t.Fatalf("job after audit failure = %s/%d; want queued/0", state, attempts)
		}
		env.svc = targetidentity.NewService(testPool, audit.New(testPool))
		lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
		if err != nil {
			t.Fatalf("consume rolled-back job: %v", err)
		}
		if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
			JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
			Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeFailed, FailureCategory: targetidentity.FailureNoCompatibleWorker},
		}); err != nil {
			t.Fatalf("finish rolled-back job fixture: %v", err)
		}
	})

	t.Run("completion", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
		lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolSSH})
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
		if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
			JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
			Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, Evidence: []targetidentity.Evidence{sshEvidence("rollback-complete")}},
		}); !errors.Is(err, errAuditRejected) {
			t.Fatalf("complete error = %v; want audit rejection", err)
		}
		var state string
		if err := testPool.QueryRow(env.ctx, `SELECT state FROM target_probe_jobs WHERE id=$1`, lease.JobID).Scan(&state); err != nil {
			t.Fatalf("read rolled-back completion: %v", err)
		}
		if state != "leased" {
			t.Fatalf("job after audit failure = %q; want leased", state)
		}
		var observations int
		if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_identity_observations WHERE job_id=$1`, lease.JobID).Scan(&observations); err != nil {
			t.Fatalf("count rolled-back observations: %v", err)
		}
		if observations != 0 {
			t.Fatalf("observations after audit failure = %d; want 0", observations)
		}
	})

	t.Run("approval", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("rollback-approve"))
		evidence := env.evidence(t)[0]
		env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
		if _, _, err := env.svc.Approve(env.ctx, targetidentity.ApproveRequest{
			AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence.ObservationID,
			EvidenceID:          evidence.ID,
			SelectedFingerprint: evidence.Fingerprint, Source: targetidentity.TrustSourceManual, ActorID: env.actor,
		}); !errors.Is(err, errAuditRejected) {
			t.Fatalf("approve error = %v; want audit rejection", err)
		}
		anchors, err := env.svc.ListAnchors(env.ctx, env.asset)
		if err != nil {
			t.Fatalf("list anchors: %v", err)
		}
		if len(anchors) != 0 {
			t.Fatalf("anchors after audit failure = %d; want 0", len(anchors))
		}
	})

	t.Run("revocation", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("rollback-revoke"))
		evidence := env.evidence(t)[0]
		anchor := env.approve(t, evidence.ObservationID, evidence.Fingerprint, time.Time{})
		env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
		if _, err := env.svc.RevokeAnchor(env.ctx, targetidentity.RevokeAnchorRequest{
			AssetID: env.asset, ExpectedRevision: 1, AnchorID: anchor.ID, ActorID: env.actor, Reason: "must roll back",
		}); !errors.Is(err, errAuditRejected) {
			t.Fatalf("revoke error = %v; want audit rejection", err)
		}
		anchors, err := env.svc.ListAnchors(env.ctx, env.asset)
		if err != nil {
			t.Fatalf("list anchors: %v", err)
		}
		if len(anchors) != 1 || !anchors[0].RevokedAt.IsZero() {
			t.Fatalf("anchor after audit failure = %#v; want active", anchors)
		}
	})

	t.Run("session mismatch", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
		if _, err := env.svc.RecordSessionMismatch(env.ctx, targetidentity.SessionMismatchRequest{
			AssetID: env.asset, EndpointRevision: 1, WorkerID: env.worker,
			Evidence: []targetidentity.Evidence{sshEvidence("rollback-mismatch")},
		}); !errors.Is(err, errAuditRejected) {
			t.Fatalf("mismatch error = %v; want audit rejection", err)
		}
		var observations int
		if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_identity_observations WHERE asset_id=$1`, env.asset).Scan(&observations); err != nil {
			t.Fatalf("count rolled-back mismatch: %v", err)
		}
		if observations != 0 {
			t.Fatalf("observations after audit failure = %d; want 0", observations)
		}
	})
}
