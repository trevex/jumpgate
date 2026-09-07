package targetidentity_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

func TestQueueProbeRequestIDReplayAndConflict(t *testing.T) {
	env := newTargetIdentityEnv(t)
	requestID := uuid.New()
	req := targetidentity.QueueProbeRequest{
		RequestID: requestID, AssetID: env.asset, EndpointRevision: 1,
		Reason: targetidentity.ProbeReasonManual, RequestedBy: env.actor,
	}
	first, err := env.svc.QueueProbe(env.ctx, req)
	if err != nil {
		t.Fatalf("first queue: %v", err)
	}
	replay, err := env.svc.QueueProbe(env.ctx, req)
	if err != nil {
		t.Fatalf("replay queue: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("replay job = %s, want original %s", replay.ID, first.ID)
	}
	conflict := req
	conflict.MaxAttempts = 7
	if _, err := env.svc.QueueProbe(env.ctx, conflict); !errors.Is(err, targetidentity.ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v, want ErrIdempotencyConflict", err)
	}
	// Do not leave a globally claimable job behind for subsequent harnesses.
	env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionRefused)
}

func TestConcurrentIdenticalRequestIDCommitsExactlyOneMutation(t *testing.T) {
	env := newTargetIdentityEnv(t)
	requestID := uuid.New()
	req := targetidentity.QueueProbeRequest{
		RequestID: requestID, AssetID: env.asset, EndpointRevision: 1,
		Reason: targetidentity.ProbeReasonManual, RequestedBy: env.actor,
	}
	beforeAudit, err := env.q.CountOutbox(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		job targetidentity.ProbeJob
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			job, err := env.svc.QueueProbe(env.ctx, req)
			results <- result{job: job, err: err}
		}()
	}
	close(start)
	first := <-results
	second := <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent calls = %v/%v", first.err, second.err)
	}
	if first.job.ID != second.job.ID {
		t.Fatalf("concurrent replay IDs = %s/%s, want identical", first.job.ID, second.job.ID)
	}
	var jobs, keys int
	if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, env.asset).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_identity_mutation_requests WHERE request_id = $1`, requestID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	afterAudit, err := env.q.CountOutbox(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || keys != 1 || afterAudit-beforeAudit != 1 {
		t.Fatalf("concurrent mutation counts jobs/keys/audit = %d/%d/%d, want 1/1/1", jobs, keys, afterAudit-beforeAudit)
	}
	env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionRefused)
}

func TestRequestIDBindsActorAssetAndOperation(t *testing.T) {
	env := newTargetIdentityEnv(t)
	other := newTargetIdentityEnv(t)
	requestID := uuid.New()
	seed := targetidentity.QueueProbeRequest{
		RequestID: requestID, AssetID: env.asset, EndpointRevision: 1,
		Reason: targetidentity.ProbeReasonManual, RequestedBy: env.actor,
	}
	if _, err := env.svc.QueueProbe(env.ctx, seed); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "actor",
			call: func() error {
				conflict := seed
				conflict.RequestedBy = other.actor
				_, err := env.svc.QueueProbe(env.ctx, conflict)
				return err
			},
		},
		{
			name: "asset",
			call: func() error {
				conflict := seed
				conflict.AssetID = other.asset
				_, err := env.svc.QueueProbe(env.ctx, conflict)
				return err
			},
		},
		{
			name: "operation",
			call: func() error {
				_, err := env.svc.RevokeAnchor(env.ctx, targetidentity.RevokeAnchorRequest{
					RequestID: requestID, AssetID: env.asset, ExpectedRevision: 1,
					AnchorID: uuid.New(), ActorID: env.actor, Reason: "operation binding",
				})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, targetidentity.ErrIdempotencyConflict) {
				t.Fatalf("conflict error = %v, want ErrIdempotencyConflict", err)
			}
		})
	}
	env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionRefused)
}

func TestQueueProbeAuditFailureRollsBackRequestIDClaim(t *testing.T) {
	env := newTargetIdentityEnv(t)
	requestID := uuid.New()
	req := targetidentity.QueueProbeRequest{
		RequestID: requestID, AssetID: env.asset, EndpointRevision: 1,
		Reason: targetidentity.ProbeReasonManual, RequestedBy: env.actor,
	}
	env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
	if _, err := env.svc.QueueProbe(env.ctx, req); !errors.Is(err, errAuditRejected) {
		t.Fatalf("queue audit failure = %v, want errAuditRejected", err)
	}
	var jobs, keys int
	if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_probe_jobs WHERE asset_id = $1`, env.asset).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(env.ctx, `SELECT count(*) FROM target_identity_mutation_requests WHERE request_id = $1`, requestID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 || keys != 0 {
		t.Fatalf("rolled-back queue jobs/keys = %d/%d, want 0/0", jobs, keys)
	}
	env.svc = targetidentity.NewService(testPool, audit.New(testPool))
	if _, err := env.svc.QueueProbe(env.ctx, req); err != nil {
		t.Fatalf("retry rolled-back queue request: %v", err)
	}
	env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionRefused)
}

func TestApproveEvidenceBatchIsAtomicAndIdempotent(t *testing.T) {
	t.Run("failure rolls back every anchor", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("batch-valid"))
		evidence := env.evidence(t)[0]
		_, _, err := env.svc.ApproveEvidenceBatch(env.ctx, targetidentity.ApproveEvidenceBatchRequest{
			RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1,
			ObservationID: evidence.ObservationID, EvidenceIDs: []uuid.UUID{evidence.ID, uuid.New()},
			Source: targetidentity.TrustSourceManual, ActorID: env.actor,
		})
		if !errors.Is(err, targetidentity.ErrEvidenceNotFound) {
			t.Fatalf("batch error = %v, want ErrEvidenceNotFound", err)
		}
		anchors, listErr := env.svc.ListAnchors(env.ctx, env.asset)
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(anchors) != 0 {
			t.Fatalf("anchors after failed batch = %d, want 0", len(anchors))
		}
	})

	t.Run("duplicate IDs rejected before mutation", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("batch-duplicate"))
		evidence := env.evidence(t)[0]
		_, _, err := env.svc.ApproveEvidenceBatch(env.ctx, targetidentity.ApproveEvidenceBatchRequest{
			RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1,
			ObservationID: evidence.ObservationID, EvidenceIDs: []uuid.UUID{evidence.ID, evidence.ID},
			Source: targetidentity.TrustSourceManual, ActorID: env.actor,
		})
		if !errors.Is(err, targetidentity.ErrInvalidRequest) {
			t.Fatalf("duplicate batch error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("audit failure rolls back all inserts and the key claim", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("batch-audit-one"), sshEvidence("batch-audit-two"))
		evidence := env.evidence(t)
		req := targetidentity.ApproveEvidenceBatchRequest{
			RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1, ObservationID: evidence[0].ObservationID,
			EvidenceIDs: []uuid.UUID{evidence[0].ID, evidence[1].ID}, Source: targetidentity.TrustSourceManual, ActorID: env.actor,
		}
		env.svc = targetidentity.NewService(testPool, failingEnqueuer{})
		if _, _, err := env.svc.ApproveEvidenceBatch(env.ctx, req); !errors.Is(err, errAuditRejected) {
			t.Fatalf("batch audit failure = %v, want errAuditRejected", err)
		}
		anchors, err := env.svc.ListAnchors(env.ctx, env.asset)
		if err != nil {
			t.Fatal(err)
		}
		if len(anchors) != 0 {
			t.Fatalf("anchors after batch audit failure = %d, want 0", len(anchors))
		}
		env.svc = targetidentity.NewService(testPool, audit.New(testPool))
		anchors, _, err = env.svc.ApproveEvidenceBatch(env.ctx, req)
		if err != nil || len(anchors) != 2 {
			t.Fatalf("retry rolled-back key = %d/%v, want 2/nil", len(anchors), err)
		}
	})

	t.Run("success emits one audit and replays original result", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("batch-one"), sshEvidence("batch-two"))
		evidence := env.evidence(t)
		before, err := env.q.CountOutbox(env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		req := targetidentity.ApproveEvidenceBatchRequest{
			RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1,
			ObservationID: evidence[0].ObservationID, EvidenceIDs: []uuid.UUID{evidence[0].ID, evidence[1].ID},
			Source: targetidentity.TrustSourceManual, ActorID: env.actor,
		}
		first, firstStatus, err := env.svc.ApproveEvidenceBatch(env.ctx, req)
		if err != nil {
			t.Fatalf("approve batch: %v", err)
		}
		replay, replayStatus, err := env.svc.ApproveEvidenceBatch(env.ctx, req)
		if err != nil {
			t.Fatalf("replay batch: %v", err)
		}
		if len(first) != 2 || len(replay) != 2 || first[0].ID != replay[0].ID || first[1].ID != replay[1].ID || firstStatus != replayStatus {
			t.Fatalf("replay differs: first=%v/%s replay=%v/%s", first, firstStatus, replay, replayStatus)
		}
		after, err := env.q.CountOutbox(env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got := after - before; got != 1 {
			t.Fatalf("batch audit events = %d, want 1", got)
		}
		conflict := req
		conflict.Source = targetidentity.TrustSourceTOFU
		if _, _, err := env.svc.ApproveEvidenceBatch(env.ctx, conflict); !errors.Is(err, targetidentity.ErrIdempotencyConflict) {
			t.Fatalf("conflicting batch replay error = %v, want ErrIdempotencyConflict", err)
		}
	})
}

func TestApproveCARequestIDReplayAndConflict(t *testing.T) {
	env := newTargetIdentityEnvForProtocol(t, targetidentity.ProtocolPostgres)
	now := time.Now().UTC()
	current := now
	env.svc = targetidentity.NewService(testPool, audit.New(testPool), targetidentity.WithClock(func() time.Time { return current }))
	leaf := targetidentity.Evidence{
		Kind: targetidentity.EvidenceTLSLeaf, Algorithm: "x509", Fingerprint: fingerprint("idempotent-ca-leaf"),
		PublicMaterial: "leaf", DNSNames: []string{"db.test"}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(2 * time.Hour),
	}
	env.queue(t, targetidentity.ProbeReasonOnboarding, uuid.Nil)
	lease, err := env.svc.Claim(env.ctx, targetidentity.ClaimRequest{WorkerID: env.worker, Protocol: targetidentity.ProtocolPostgres})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Complete(env.ctx, targetidentity.CompleteRequest{
		JobID: lease.JobID, WorkerID: env.worker, LeaseToken: lease.Token,
		Result: targetidentity.ProbeResult{Outcome: targetidentity.ProbeSucceeded, TLS: &targetidentity.TLSMetadata{ServerName: "db.test"}, Evidence: []targetidentity.Evidence{leaf}},
	}); err != nil {
		t.Fatal(err)
	}
	persisted := env.evidence(t)[0]
	rootMaterial, rootFingerprint := testCAPEM(t, "idempotent-ca-root")
	req := targetidentity.ApproveRequest{
		RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1, ObservationID: persisted.ObservationID,
		SelectedFingerprint: rootFingerprint, AnchorKind: targetidentity.AnchorTLSCA, SuppliedAlgorithm: "x509",
		SuppliedPublicMaterial: rootMaterial, ValidatedEvidenceID: persisted.ID, RequiredDNSNames: []string{"db.test"},
		Source: targetidentity.TrustSourceManual, ActorID: env.actor, ExpiresAt: now.Add(30 * time.Minute),
	}
	first, firstStatus, err := env.svc.Approve(env.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	// Replay precedes time-sensitive revalidation: expiry after the original
	// commit must not change its durable logical response.
	current = now.Add(time.Hour)
	replay, replayStatus, err := env.svc.Approve(env.ctx, req)
	if err != nil || replay.ID != first.ID || replayStatus != firstStatus {
		t.Fatalf("CA replay = %s/%s/%v, want %s/%s", replay.ID, replayStatus, err, first.ID, firstStatus)
	}
	conflict := req
	conflict.RequiredDNSNames = []string{"other.test"}
	if _, _, err := env.svc.Approve(env.ctx, conflict); !errors.Is(err, targetidentity.ErrIdempotencyConflict) {
		t.Fatalf("CA request_id conflict = %v", err)
	}
}

func TestRejectAndRevokeRequestIDReplay(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		if _, err := env.svc.RecordSessionMismatch(env.ctx, targetidentity.SessionMismatchRequest{
			AssetID: env.asset, EndpointRevision: 1, WorkerID: env.worker,
			SSH: &targetidentity.SSHMetadata{Banner: "SSH-2.0-test"}, Evidence: []targetidentity.Evidence{sshEvidence("reject-replay")},
		}); err != nil {
			t.Fatal(err)
		}
		observationID := env.evidence(t)[0].ObservationID
		req := targetidentity.RejectObservationRequest{RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1, ObservationID: observationID, ActorID: env.actor, Reason: "known noise"}
		first, err := env.svc.RejectObservation(env.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := env.svc.RejectObservation(env.ctx, req)
		if err != nil || replay != first {
			t.Fatalf("reject replay = %s/%v, want %s", replay, err, first)
		}
		conflict := req
		conflict.Reason = "different"
		if _, err := env.svc.RejectObservation(env.ctx, conflict); !errors.Is(err, targetidentity.ErrIdempotencyConflict) {
			t.Fatalf("reject conflict = %v", err)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		env := newTargetIdentityEnv(t)
		env.complete(t, sshEvidence("revoke-replay"))
		evidence := env.evidence(t)[0]
		anchor := env.approve(t, evidence.ObservationID, evidence.Fingerprint, time.Time{})
		req := targetidentity.RevokeAnchorRequest{RequestID: uuid.New(), AssetID: env.asset, ExpectedRevision: 1, AnchorID: anchor.ID, ActorID: env.actor, Reason: "rotation"}
		first, err := env.svc.RevokeAnchor(env.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := env.svc.RevokeAnchor(env.ctx, req)
		if err != nil || replay != first {
			t.Fatalf("revoke replay = %s/%v, want %s", replay, err, first)
		}
		conflict := req
		conflict.Reason = "different"
		if _, err := env.svc.RevokeAnchor(env.ctx, conflict); !errors.Is(err, targetidentity.ErrIdempotencyConflict) {
			t.Fatalf("revoke conflict = %v", err)
		}
	})
}

func TestDatabaseKeysetPagesProbeObservationAndAnchorHistory(t *testing.T) {
	env := newTargetIdentityEnv(t)
	for i := 0; i < 5; i++ {
		if _, err := env.svc.QueueProbe(env.ctx, targetidentity.QueueProbeRequest{
			RequestID: uuid.New(), AssetID: env.asset, EndpointRevision: 1, Reason: targetidentity.ProbeReasonManual, RequestedBy: env.actor,
		}); err != nil {
			t.Fatal(err)
		}
	}
	probePage, more, err := env.svc.ListProbesPage(env.ctx, env.asset, targetidentity.PageRequest{Limit: 2})
	if err != nil || len(probePage) != 2 || !more {
		t.Fatalf("probe page 1 = %d/%v/%v", len(probePage), more, err)
	}
	probePage2, more2, err := env.svc.ListProbesPage(env.ctx, env.asset, targetidentity.PageRequest{Limit: 2, AfterTime: probePage[1].CreatedAt, AfterID: probePage[1].ID})
	if err != nil || len(probePage2) != 2 || !more2 || probePage2[0].ID == probePage[0].ID || probePage2[0].ID == probePage[1].ID {
		t.Fatalf("probe page 2 invalid: %v/%v/%v", probePage2, more2, err)
	}
	for i := 0; i < 5; i++ {
		env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionRefused)
	}

	observationEnv := newTargetIdentityEnv(t)
	for i := 0; i < 3; i++ {
		if _, err := observationEnv.svc.RecordSessionMismatch(observationEnv.ctx, targetidentity.SessionMismatchRequest{
			AssetID: observationEnv.asset, EndpointRevision: 1, WorkerID: observationEnv.worker,
			ObservedAt: time.Now().Add(time.Duration(i) * time.Second), SSH: &targetidentity.SSHMetadata{Banner: "SSH-2.0-test"},
			Evidence: []targetidentity.Evidence{sshEvidence(uuid.NewString())},
		}); err != nil {
			t.Fatal(err)
		}
	}
	observationPage, observationsMore, err := observationEnv.svc.ListObservationsPage(observationEnv.ctx, observationEnv.asset, targetidentity.PageRequest{Limit: 2})
	if err != nil || len(observationPage) != 2 || !observationsMore || len(observationPage[0].Evidence) != 1 || len(observationPage[1].Evidence) != 1 {
		t.Fatalf("observation page = %v/%v/%v", observationPage, observationsMore, err)
	}
	observationPage2, observationsMore2, err := observationEnv.svc.ListObservationsPage(observationEnv.ctx, observationEnv.asset, targetidentity.PageRequest{Limit: 2, AfterTime: observationPage[1].ObservedAt, AfterID: observationPage[1].ID})
	if err != nil || len(observationPage2) != 1 || observationsMore2 {
		t.Fatalf("observation page 2 = %v/%v/%v", observationPage2, observationsMore2, err)
	}

	approvalEnv := newTargetIdentityEnv(t)
	approvalEnv.complete(t, sshEvidence("anchor-1"), sshEvidence("anchor-2"), sshEvidence("anchor-3"))
	evidence := approvalEnv.evidence(t)
	ids := []uuid.UUID{evidence[0].ID, evidence[1].ID, evidence[2].ID}
	if _, _, err := approvalEnv.svc.ApproveEvidenceBatch(approvalEnv.ctx, targetidentity.ApproveEvidenceBatchRequest{
		RequestID: uuid.New(), AssetID: approvalEnv.asset, ExpectedRevision: 1, ObservationID: evidence[0].ObservationID,
		EvidenceIDs: ids, Source: targetidentity.TrustSourceManual, ActorID: approvalEnv.actor,
	}); err != nil {
		t.Fatal(err)
	}
	anchorPage, anchorsMore, err := approvalEnv.svc.ListAnchorsPage(approvalEnv.ctx, approvalEnv.asset, targetidentity.PageRequest{Limit: 2})
	if err != nil || len(anchorPage) != 2 || !anchorsMore {
		t.Fatalf("anchor page = %v/%v/%v", anchorPage, anchorsMore, err)
	}
	anchorPage2, anchorsMore2, err := approvalEnv.svc.ListAnchorsPage(approvalEnv.ctx, approvalEnv.asset, targetidentity.PageRequest{Limit: 2, AfterTime: anchorPage[1].ApprovedAt, AfterID: anchorPage[1].ID})
	if err != nil || len(anchorPage2) != 1 || anchorsMore2 {
		t.Fatalf("anchor page 2 = %v/%v/%v", anchorPage2, anchorsMore2, err)
	}
}
