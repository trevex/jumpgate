package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	targetidentityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1/targetidentityv1connect"
)

// stubTargetIdentity serves the TargetIdentityService. GetProbe replays a
// scripted sequence of states (the last repeats) so polling can be exercised
// deterministically; the mutating RPCs capture their request for assertions.
type stubTargetIdentity struct {
	targetidentityv1connect.UnimplementedTargetIdentityServiceHandler

	probeStates   []targetidentityv1.ProbeState
	getProbeCalls int

	observations []*targetidentityv1.Observation
	anchors      []*targetidentityv1.TrustAnchor

	gotStartProbe      *targetidentityv1.StartProbeRequest
	gotApproveEvidence *targetidentityv1.ApproveEvidenceRequest
	gotApproveCA       *targetidentityv1.ApproveCARequest
	gotRevoke          *targetidentityv1.RevokeTrustAnchorRequest

	approveErr error
}

const (
	tiAssetID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tiProbeID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	tiObsID   = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	tiEvidID  = "dddddddd-dddd-dddd-dddd-dddddddddddd"
)

func (s *stubTargetIdentity) StartProbe(_ context.Context, req *connect.Request[targetidentityv1.StartProbeRequest]) (*connect.Response[targetidentityv1.StartProbeResponse], error) {
	s.gotStartProbe = req.Msg
	return connect.NewResponse(&targetidentityv1.StartProbeResponse{Probe: &targetidentityv1.ProbeJob{
		Id:               tiProbeID,
		AssetId:          req.Msg.GetAssetId(),
		EndpointRevision: req.Msg.GetExpectedEndpointRevision(),
		State:            targetidentityv1.ProbeState_PROBE_STATE_QUEUED,
	}}), nil
}

func (s *stubTargetIdentity) GetProbe(_ context.Context, req *connect.Request[targetidentityv1.GetProbeRequest]) (*connect.Response[targetidentityv1.GetProbeResponse], error) {
	state := targetidentityv1.ProbeState_PROBE_STATE_QUEUED
	if len(s.probeStates) > 0 {
		i := s.getProbeCalls
		if i >= len(s.probeStates) {
			i = len(s.probeStates) - 1
		}
		state = s.probeStates[i]
	}
	s.getProbeCalls++
	return connect.NewResponse(&targetidentityv1.GetProbeResponse{Probe: &targetidentityv1.ProbeJob{
		Id:               req.Msg.GetProbeId(),
		AssetId:          req.Msg.GetAssetId(),
		EndpointRevision: 1,
		State:            state,
		FailureDetail:    "connection refused",
	}}), nil
}

func (s *stubTargetIdentity) ListObservations(_ context.Context, _ *connect.Request[targetidentityv1.ListObservationsRequest]) (*connect.Response[targetidentityv1.ListObservationsResponse], error) {
	return connect.NewResponse(&targetidentityv1.ListObservationsResponse{Observations: s.observations}), nil
}

func (s *stubTargetIdentity) ApproveEvidence(_ context.Context, req *connect.Request[targetidentityv1.ApproveEvidenceRequest]) (*connect.Response[targetidentityv1.ApproveEvidenceResponse], error) {
	s.gotApproveEvidence = req.Msg
	if s.approveErr != nil {
		return nil, s.approveErr
	}
	return connect.NewResponse(&targetidentityv1.ApproveEvidenceResponse{
		Status:       targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
		TrustAnchors: []*targetidentityv1.TrustAnchor{{Id: "anchor-1", AssetId: req.Msg.GetAssetId(), Sha256Fingerprint: "SHA256:abc"}},
	}), nil
}

func (s *stubTargetIdentity) ApproveCA(_ context.Context, req *connect.Request[targetidentityv1.ApproveCARequest]) (*connect.Response[targetidentityv1.ApproveCAResponse], error) {
	s.gotApproveCA = req.Msg
	return connect.NewResponse(&targetidentityv1.ApproveCAResponse{
		Status:      targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
		TrustAnchor: &targetidentityv1.TrustAnchor{Id: "anchor-ca", AssetId: req.Msg.GetAssetId()},
	}), nil
}

func (s *stubTargetIdentity) ListTrustAnchors(_ context.Context, _ *connect.Request[targetidentityv1.ListTrustAnchorsRequest]) (*connect.Response[targetidentityv1.ListTrustAnchorsResponse], error) {
	return connect.NewResponse(&targetidentityv1.ListTrustAnchorsResponse{TrustAnchors: s.anchors}), nil
}

func (s *stubTargetIdentity) RevokeTrustAnchor(_ context.Context, req *connect.Request[targetidentityv1.RevokeTrustAnchorRequest]) (*connect.Response[targetidentityv1.RevokeTrustAnchorResponse], error) {
	s.gotRevoke = req.Msg
	return connect.NewResponse(&targetidentityv1.RevokeTrustAnchorResponse{Status: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_PENDING_VERIFICATION}), nil
}

// resetIdentityFlags restores mutated package-global flag/TTY state between runs.
func resetIdentityFlags() {
	flagOutput = "table"
	identityFlagValues = identityFlags{}
	probeEndpointRevision = 1
	probeWaitTimeout = 60_000_000_000 // 60s
	revokeReason = ""
	stdinIsTTY = defaultStdinIsTTY
	for _, c := range []*cobra.Command{assetsProbeCmd, assetsIdentityApproveCmd, assetsIdentityRevokeCmd} {
		c.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
	}
	rootCmd.SetIn(nil)
}

func newTargetIdentityStub(t *testing.T, s *stubTargetIdentity) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(targetidentityv1connect.NewTargetIdentityServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// obsWithFingerprint builds a succeeded observation carrying one SSH host-key
// evidence item with the given fingerprint at endpoint revision 7.
func obsWithFingerprint(fp string) *targetidentityv1.Observation {
	return &targetidentityv1.Observation{
		Id:               tiObsID,
		ProbeId:          tiProbeID,
		AssetId:          tiAssetID,
		EndpointRevision: 7,
		Outcome:          targetidentityv1.ObservationOutcome_OBSERVATION_OUTCOME_SUCCEEDED,
		ObservedAtUnixMs: 1000,
		Evidence: []*targetidentityv1.Evidence{{
			Id:                tiEvidID,
			Kind:              targetidentityv1.EvidenceKind_EVIDENCE_KIND_SSH_HOST_KEY,
			Algorithm:         "ssh-ed25519",
			Sha256Fingerprint: fp,
		}},
	}
}

func setupTI(t *testing.T, s *stubTargetIdentity) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newTargetIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetIdentityFlags)
}

func TestTargetIdentityProbeSuccessJSON(t *testing.T) {
	s := &stubTargetIdentity{
		probeStates:  []targetidentityv1.ProbeState{targetidentityv1.ProbeState_PROBE_STATE_QUEUED, targetidentityv1.ProbeState_PROBE_STATE_SUCCEEDED},
		observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")},
	}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "probe", tiAssetID, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	// stdout must be a clean JSON document (progress went to stderr).
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not parseable JSON: %v\nstdout=%s", err, out.String())
	}
	if !strings.Contains(out.String(), "SHA256:abc") {
		t.Fatalf("observed fingerprint missing from stdout: %s", out.String())
	}
	// The started probe carried a positive expected endpoint revision.
	if s.gotStartProbe == nil || s.gotStartProbe.GetExpectedEndpointRevision() <= 0 {
		t.Fatalf("StartProbe expected_endpoint_revision not positive: %+v", s.gotStartProbe)
	}
}

func TestTargetIdentityProbeFailedIsError(t *testing.T) {
	s := &stubTargetIdentity{probeStates: []targetidentityv1.ProbeState{targetidentityv1.ProbeState_PROBE_STATE_FAILED}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "probe", tiAssetID})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected a non-nil error when the probe fails")
	}
}

func TestTargetIdentityApproveExpectedFingerprintMatch(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID, "--expected-fingerprint", "SHA256:abc"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	ae := s.gotApproveEvidence
	if ae == nil {
		t.Fatal("ApproveEvidence was not called on an exact match")
	}
	// Approval passed the exact observation + endpoint revision that was observed.
	if ae.GetObservationId() != tiObsID {
		t.Fatalf("approved observation_id=%q, want %q", ae.GetObservationId(), tiObsID)
	}
	if ae.GetExpectedEndpointRevision() != 7 {
		t.Fatalf("approval revision=%d, want the observed 7", ae.GetExpectedEndpointRevision())
	}
	if len(ae.GetEvidenceIds()) != 1 || ae.GetEvidenceIds()[0] != tiEvidID {
		t.Fatalf("approved evidence ids=%v, want [%s]", ae.GetEvidenceIds(), tiEvidID)
	}
	if ae.GetSource() != targetidentityv1.TrustSource_TRUST_SOURCE_EXPECTED {
		t.Fatalf("source=%v, want EXPECTED", ae.GetSource())
	}
}

func TestTargetIdentityApproveExpectedFingerprintMismatch(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID, "--expected-fingerprint", "SHA256:WRONG"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected a mismatch error")
	}
	if s.gotApproveEvidence != nil {
		t.Fatal("no approval must happen on a fingerprint mismatch")
	}
}

func TestTargetIdentityApproveMutualExclusion(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID, "--auto-approve", "--expected-fingerprint", "SHA256:abc"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error: --auto-approve and --expected-fingerprint are mutually exclusive")
	}
	if s.gotApproveEvidence != nil {
		t.Fatal("mutual-exclusion must be rejected before any approval RPC")
	}
}

func TestTargetIdentityApproveNonTTYRefusal(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)

	// Non-interactive (default under `go test`): no flag, no prompt possible.
	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected a refusal in a non-interactive context without an automation mode")
	}
	if s.gotApproveEvidence != nil {
		t.Fatal("must not approve without an explicit decision")
	}
}

func TestTargetIdentityApproveInteractivePromptYes(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)
	stdinIsTTY = func() bool { return true }

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetIn(strings.NewReader("y\n"))
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	if !strings.Contains(errb.String(), "Approve this observed identity?") {
		t.Fatalf("prompt not shown on stderr: %s", errb.String())
	}
	if s.gotApproveEvidence == nil {
		t.Fatal("a 'y' answer must approve")
	}
	if s.gotApproveEvidence.GetSource() != targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL {
		t.Fatalf("interactive approval source=%v, want MANUAL", s.gotApproveEvidence.GetSource())
	}
}

func TestTargetIdentityApproveInteractivePromptDefaultNo(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)
	stdinIsTTY = func() bool { return true }

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetIn(strings.NewReader("\n")) // bare Enter → default NO
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	if s.gotApproveEvidence != nil {
		t.Fatal("the default answer is NO; nothing must be approved")
	}
}

func TestTargetIdentityApproveAutoApproveTOFUDisabled(t *testing.T) {
	s := &stubTargetIdentity{
		observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")},
		approveErr:   connect.NewError(connect.CodeFailedPrecondition, errors.New("tofu is disabled for this asset")),
	}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID, "--auto-approve"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected the server's TOFU-disabled rejection to surface as an error")
	}
	if s.gotApproveEvidence.GetSource() != targetidentityv1.TrustSource_TRUST_SOURCE_TOFU {
		t.Fatalf("--auto-approve must request a TOFU trust source, got %v", s.gotApproveEvidence.GetSource())
	}
}

func TestTargetIdentityApproveDNSNameRequiresCA(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID, "--expected-dns-name", "db.prod"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("--expected-dns-name is only meaningful with --trusted-ca-file")
	}
}

func TestTargetIdentityApproveCA(t *testing.T) {
	s := &stubTargetIdentity{observations: []*targetidentityv1.Observation{obsWithFingerprint("SHA256:abc")}}
	setupTI(t, s)

	caFile := t.TempDir() + "/ca.pub"
	if err := os.WriteFile(caFile, []byte("ssh-ed25519 AAAAC3CApublickey comment"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "approve", tiAssetID, "--trusted-ca-file", caFile, "--expected-dns-name", "db.prod"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	ca := s.gotApproveCA
	if ca == nil {
		t.Fatal("ApproveCA was not called for --trusted-ca-file")
	}
	if !strings.Contains(ca.GetPublicMaterial(), "publickey") {
		t.Fatalf("CA public material not forwarded: %q", ca.GetPublicMaterial())
	}
	if ca.GetObservationId() != tiObsID || ca.GetValidatedEvidenceId() != tiEvidID {
		t.Fatalf("CA approval not bound to the observed evidence: obs=%q evid=%q", ca.GetObservationId(), ca.GetValidatedEvidenceId())
	}
	if len(ca.GetRequiredDnsNames()) != 1 || ca.GetRequiredDnsNames()[0] != "db.prod" {
		t.Fatalf("required dns names=%v, want [db.prod]", ca.GetRequiredDnsNames())
	}
}

func TestTargetIdentityList(t *testing.T) {
	s := &stubTargetIdentity{anchors: []*targetidentityv1.TrustAnchor{{
		Id:                "anchor-1",
		AssetId:           tiAssetID,
		EndpointRevision:  7,
		Kind:              targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_SSH_HOST_KEY,
		Algorithm:         "ssh-ed25519",
		Sha256Fingerprint: "SHA256:abc",
		Source:            targetidentityv1.TrustSource_TRUST_SOURCE_TOFU,
	}}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "list", tiAssetID, "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "anchor-1") || !strings.Contains(got, "SHA256:abc") {
		t.Fatalf("anchor row missing: %s", got)
	}
}

func TestTargetIdentityRevoke(t *testing.T) {
	s := &stubTargetIdentity{anchors: []*targetidentityv1.TrustAnchor{{
		Id:               "anchor-1",
		AssetId:          tiAssetID,
		EndpointRevision: 7,
	}}}
	setupTI(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "identity", "revoke", tiAssetID, "anchor-1", "--reason", "rotated"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	if s.gotRevoke == nil {
		t.Fatal("RevokeTrustAnchor was not called")
	}
	if s.gotRevoke.GetTrustAnchorId() != "anchor-1" {
		t.Fatalf("revoked anchor id=%q", s.gotRevoke.GetTrustAnchorId())
	}
	// The revoked anchor's own endpoint revision is used for the optimistic check.
	if s.gotRevoke.GetExpectedEndpointRevision() != 7 {
		t.Fatalf("revoke revision=%d, want 7", s.gotRevoke.GetExpectedEndpointRevision())
	}
	if s.gotRevoke.GetReason() != "rotated" {
		t.Fatalf("reason=%q", s.gotRevoke.GetReason())
	}
}
