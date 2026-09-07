package targetidentity_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	targetidentityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

func grantAssetCapability(t *testing.T, userID, assetID uuid.UUID, capability string) {
	t.Helper()
	q := sqlc.New(testPool)
	role, err := q.CreateRole(context.Background(), sqlc.CreateRoleParams{Name: "ti-handler-" + uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	scope, action, qualifier := authz.NormalizeCap(capability)
	if err := q.InsertRoleCapability(context.Background(), sqlc.InsertRoleCapabilityParams{RoleID: role.ID, Scope: scope, Action: action, Qualifier: qualifier}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(context.Background(), sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgtype.UUID{Bytes: assetID, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: userID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
}

func handlerContext(userID uuid.UUID) context.Context {
	return auth.WithUser(context.Background(), auth.CurrentUser{ID: userID, Email: userID.String() + "@example.test"})
}

func newTargetIdentityHandler(env *targetIdentityEnv) *targetidentity.Handler {
	return targetidentity.NewHandler(env.svc, apiguard.New(authz.New(testPool), env.q))
}

func TestHandlerHidesAssetBeforeCapabilityCheck(t *testing.T) {
	env := newTargetIdentityEnv(t)
	h := newTargetIdentityHandler(env)
	_, err := h.GetVerificationStatus(handlerContext(env.actor), connect.NewRequest(&targetidentityv1.GetVerificationStatusRequest{AssetId: env.asset.String()}))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("code = %v, want not_found", got)
	}
}

func TestHandlerUsesExactCapabilities(t *testing.T) {
	tests := []struct {
		name string
		cap  string
		call func(*targetidentity.Handler, context.Context, uuid.UUID) error
	}{
		{"probe", authz.AssetProbeCap, func(h *targetidentity.Handler, ctx context.Context, assetID uuid.UUID) error {
			_, err := h.StartProbe(ctx, connect.NewRequest(&targetidentityv1.StartProbeRequest{RequestId: uuid.NewString(), AssetId: assetID.String(), ExpectedEndpointRevision: 1}))
			return err
		}},
		{"read", authz.AssetIdentityReadCap, func(h *targetidentity.Handler, ctx context.Context, assetID uuid.UUID) error {
			_, err := h.GetVerificationStatus(ctx, connect.NewRequest(&targetidentityv1.GetVerificationStatusRequest{AssetId: assetID.String()}))
			return err
		}},
		{"approve", authz.AssetIdentityApproveCap, func(h *targetidentity.Handler, ctx context.Context, assetID uuid.UUID) error {
			_, err := h.RejectObservation(ctx, connect.NewRequest(&targetidentityv1.RejectObservationRequest{
				RequestId: uuid.NewString(), AssetId: assetID.String(), ExpectedEndpointRevision: 1, ObservationId: uuid.NewString(),
			}))
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTargetIdentityEnv(t)
			grantAssetCapability(t, env.actor, env.asset, tt.cap)
			err := tt.call(newTargetIdentityHandler(env), handlerContext(env.actor), env.asset)
			if tt.cap == authz.AssetProbeCap && err == nil {
				if _, cleanupErr := testPool.Exec(env.ctx, `UPDATE target_probe_jobs SET state = 'cancelled', completed_at = now() WHERE asset_id = $1 AND state = 'queued'`, env.asset); cleanupErr != nil {
					t.Fatalf("cancel test probe: %v", cleanupErr)
				}
			}
			if tt.cap == authz.AssetIdentityApproveCap {
				if connect.CodeOf(err) != connect.CodeNotFound {
					t.Fatalf("approved gate code = %v, want domain not_found", connect.CodeOf(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("exact capability rejected: %v", err)
			}
		})
	}
}

func TestEveryHandlerRejectsVisibleCallerWithoutExactCapability(t *testing.T) {
	env := newTargetIdentityEnv(t)
	grantAssetCapability(t, env.actor, env.asset, authz.AssetReadCap)
	h := newTargetIdentityHandler(env)
	ctx := handlerContext(env.actor)
	assetID := env.asset.String()
	cases := []struct {
		name string
		call func() error
	}{
		{"StartProbe", func() error {
			_, err := h.StartProbe(ctx, connect.NewRequest(&targetidentityv1.StartProbeRequest{RequestId: uuid.NewString(), AssetId: assetID, ExpectedEndpointRevision: 1}))
			return err
		}},
		{"GetProbe", func() error {
			_, err := h.GetProbe(ctx, connect.NewRequest(&targetidentityv1.GetProbeRequest{AssetId: assetID, ProbeId: uuid.NewString()}))
			return err
		}},
		{"ListProbes", func() error {
			_, err := h.ListProbes(ctx, connect.NewRequest(&targetidentityv1.ListProbesRequest{AssetId: assetID}))
			return err
		}},
		{"ListObservations", func() error {
			_, err := h.ListObservations(ctx, connect.NewRequest(&targetidentityv1.ListObservationsRequest{AssetId: assetID}))
			return err
		}},
		{"ApproveEvidence", func() error {
			_, err := h.ApproveEvidence(ctx, connect.NewRequest(&targetidentityv1.ApproveEvidenceRequest{RequestId: uuid.NewString(), AssetId: assetID, ExpectedEndpointRevision: 1, ObservationId: uuid.NewString(), EvidenceIds: []string{uuid.NewString()}, Source: targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL}))
			return err
		}},
		{"ApproveCA", func() error {
			_, err := h.ApproveCA(ctx, connect.NewRequest(&targetidentityv1.ApproveCARequest{RequestId: uuid.NewString(), AssetId: assetID, ExpectedEndpointRevision: 1, ObservationId: uuid.NewString(), ValidatedEvidenceId: uuid.NewString(), Kind: targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_TLS_CA, PublicMaterial: "ca", Source: targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL}))
			return err
		}},
		{"RejectObservation", func() error {
			_, err := h.RejectObservation(ctx, connect.NewRequest(&targetidentityv1.RejectObservationRequest{RequestId: uuid.NewString(), AssetId: assetID, ExpectedEndpointRevision: 1, ObservationId: uuid.NewString()}))
			return err
		}},
		{"ListTrustAnchors", func() error {
			_, err := h.ListTrustAnchors(ctx, connect.NewRequest(&targetidentityv1.ListTrustAnchorsRequest{AssetId: assetID}))
			return err
		}},
		{"RevokeTrustAnchor", func() error {
			_, err := h.RevokeTrustAnchor(ctx, connect.NewRequest(&targetidentityv1.RevokeTrustAnchorRequest{RequestId: uuid.NewString(), AssetId: assetID, ExpectedEndpointRevision: 1, TrustAnchorId: uuid.NewString()}))
			return err
		}},
		{"GetVerificationStatus", func() error {
			_, err := h.GetVerificationStatus(ctx, connect.NewRequest(&targetidentityv1.GetVerificationStatusRequest{AssetId: assetID}))
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := connect.CodeOf(tc.call()); got != connect.CodePermissionDenied {
				t.Fatalf("code = %v, want permission_denied", got)
			}
		})
	}
}

func TestHandlerMapsStableDomainErrors(t *testing.T) {
	env := newTargetIdentityEnv(t)
	grantAssetCapability(t, env.actor, env.asset, authz.AssetIdentityApproveCap)
	h := newTargetIdentityHandler(env)
	_, err := h.RejectObservation(handlerContext(env.actor), connect.NewRequest(&targetidentityv1.RejectObservationRequest{
		RequestId: uuid.NewString(), AssetId: env.asset.String(), ExpectedEndpointRevision: 2, ObservationId: uuid.NewString(),
	}))
	if got := connect.CodeOf(err); got != connect.CodeAborted {
		t.Fatalf("stale revision code = %v, want aborted", got)
	}
}

func TestHandlerListsAndApprovesObservedEvidence(t *testing.T) {
	env := newTargetIdentityEnv(t)
	grantAssetCapability(t, env.actor, env.asset, authz.AssetIdentityReadCap)
	grantAssetCapability(t, env.actor, env.asset, authz.AssetIdentityApproveCap)
	env.complete(t, sshEvidence("handler-roundtrip"))
	h := newTargetIdentityHandler(env)
	ctx := handlerContext(env.actor)

	listed, err := h.ListObservations(ctx, connect.NewRequest(&targetidentityv1.ListObservationsRequest{AssetId: env.asset.String(), PageSize: 10}))
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	if len(listed.Msg.Observations) != 1 || len(listed.Msg.Observations[0].Evidence) != 1 {
		t.Fatalf("observations/evidence = %d/%d, want 1/1", len(listed.Msg.Observations), len(listed.Msg.Observations[0].Evidence))
	}
	observation := listed.Msg.Observations[0]
	if observation.GetSsh().GetBanner() != "SSH-2.0-test" {
		t.Fatalf("SSH banner = %q, want SSH-2.0-test", observation.GetSsh().GetBanner())
	}

	approvalRequest := &targetidentityv1.ApproveEvidenceRequest{
		RequestId: uuid.NewString(), AssetId: env.asset.String(), ExpectedEndpointRevision: 1,
		ObservationId: observation.Id, EvidenceIds: []string{observation.Evidence[0].Id}, Source: targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL,
	}
	approved, err := h.ApproveEvidence(ctx, connect.NewRequest(approvalRequest))
	if err != nil {
		t.Fatalf("approve evidence: %v", err)
	}
	if len(approved.Msg.TrustAnchors) != 1 || approved.Msg.Status != targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED {
		t.Fatalf("approval = anchors:%d status:%v, want 1/verified", len(approved.Msg.TrustAnchors), approved.Msg.Status)
	}
	replayed, err := h.ApproveEvidence(ctx, connect.NewRequest(approvalRequest))
	if err != nil {
		t.Fatalf("replay approval: %v", err)
	}
	if len(replayed.Msg.TrustAnchors) != 1 || replayed.Msg.TrustAnchors[0].Id != approved.Msg.TrustAnchors[0].Id {
		t.Fatalf("replayed anchor = %v, want original %s", replayed.Msg.TrustAnchors, approved.Msg.TrustAnchors[0].Id)
	}
	conflict := proto.Clone(approvalRequest).(*targetidentityv1.ApproveEvidenceRequest)
	conflict.Source = targetidentityv1.TrustSource_TRUST_SOURCE_TOFU
	if _, err := h.ApproveEvidence(ctx, connect.NewRequest(conflict)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("conflicting request_id code = %v, want failed_precondition", connect.CodeOf(err))
	}
}
