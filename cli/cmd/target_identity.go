package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	"github.com/trevex/jumpgate/cli/internal/wardenclient"
	targetidentityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1"
)

// stdinIsTTY reports whether stdin is an interactive terminal. It is a package
// variable so tests can force the interactive path without a real TTY.
var stdinIsTTY = defaultStdinIsTTY

func defaultStdinIsTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// probeTimeoutError is returned when waitForProbe's deadline elapses. It is a
// distinct type so callers can tell "gave up waiting" (the durable probe keeps
// running server-side) apart from a real failure.
type probeTimeoutError struct{ probeID string }

func (e *probeTimeoutError) Error() string {
	return fmt.Sprintf("timed out waiting for probe %s to complete", e.probeID)
}

// identityFlags carries the automation/expectation choices shared by
// `assets identity approve` and the guided `assets ssh create` flow.
type identityFlags struct {
	autoApprove   bool
	expectFP      string
	trustedCAFile string
	expectedDNS   string
}

func (f identityFlags) hasExpectation() bool {
	return f.expectFP != "" || f.trustedCAFile != "" || f.expectedDNS != ""
}

// validate enforces the flag contract BEFORE any RPC: --auto-approve is
// mutually exclusive with the expectation flags, and --expected-dns-name is
// only meaningful when pinning a CA.
func (f identityFlags) validate() error {
	if f.autoApprove && f.hasExpectation() {
		return errors.New("--auto-approve is mutually exclusive with --expected-fingerprint/--trusted-ca-file/--expected-dns-name")
	}
	if f.expectedDNS != "" && f.trustedCAFile == "" {
		return errors.New("--expected-dns-name requires --trusted-ca-file")
	}
	return nil
}

// wouldPrompt reports whether resolving f needs an interactive prompt (no
// expectation, no auto-approve). Callers refuse early in a non-TTY context.
func (f identityFlags) wouldPrompt() bool { return !f.autoApprove && !f.hasExpectation() }

var (
	probeEndpointRevision int64
	probeWaitTimeout      time.Duration

	identityFlagValues identityFlags

	revokeReason string
)

var assetsProbeCmd = &cobra.Command{
	Use:   "probe <asset>",
	Short: "Probe a target's identity without releasing any credential",
	Long: "Start a credential-free identity probe against an asset, wait for it to " +
		"complete, and print the observed identity. Progress is written to stderr so " +
		"`-o json` stdout stays a clean, parseable document.",
	Args: cobra.ExactArgs(1),
	RunE: runAssetsProbe,
}

var assetsIdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Inspect and manage an asset's trusted target identity",
}

var assetsIdentityListCmd = &cobra.Command{
	Use:   "list <asset>",
	Short: "List the trust anchors approved for an asset",
	Args:  cobra.ExactArgs(1),
	RunE:  runAssetsIdentityList,
}

var assetsIdentityApproveCmd = &cobra.Command{
	Use:   "approve <asset>",
	Short: "Approve the latest observed identity of an asset",
	Long: "Approve the most recent observed identity for an asset. Provide " +
		"--expected-fingerprint or --trusted-ca-file to approve non-interactively " +
		"against an exact expectation, --auto-approve to trust whatever was observed " +
		"(TOFU), or run on a terminal to be prompted. Run `jumpgate assets probe` " +
		"first if the asset has no observation yet.",
	Args: cobra.ExactArgs(1),
	RunE: runAssetsIdentityApprove,
}

var assetsIdentityRevokeCmd = &cobra.Command{
	Use:   "revoke <asset> <trust-anchor-id>",
	Short: "Revoke a trust anchor",
	Args:  cobra.ExactArgs(2),
	RunE:  runAssetsIdentityRevoke,
}

func init() {
	assetsProbeCmd.Flags().Int64Var(&probeEndpointRevision, "endpoint-revision", 1, "endpoint revision to probe")
	assetsProbeCmd.Flags().DurationVar(&probeWaitTimeout, "wait-timeout", 60*time.Second, "how long to wait for the probe to complete")

	addApprovalFlags(assetsIdentityApproveCmd, &identityFlagValues)

	assetsIdentityRevokeCmd.Flags().StringVar(&revokeReason, "reason", "", "reason recorded with the revocation")

	assetsIdentityCmd.AddCommand(assetsIdentityListCmd)
	assetsIdentityCmd.AddCommand(assetsIdentityApproveCmd)
	assetsIdentityCmd.AddCommand(assetsIdentityRevokeCmd)

	assetsCmd.AddCommand(assetsProbeCmd)
	assetsCmd.AddCommand(assetsIdentityCmd)
}

// addApprovalFlags registers the shared approval/expectation flags onto cmd,
// binding them into f. Used by both `assets identity approve` and `assets ssh create`.
func addApprovalFlags(cmd *cobra.Command, f *identityFlags) {
	cmd.Flags().BoolVar(&f.autoApprove, "auto-approve", false, "trust whatever the probe observes (TOFU); mutually exclusive with the expectation flags")
	cmd.Flags().StringVar(&f.expectFP, "expected-fingerprint", "", "approve only if the observed SHA256 fingerprint matches exactly")
	cmd.Flags().StringVar(&f.trustedCAFile, "trusted-ca-file", "", "approve a CA read from this file (pins issuing authority instead of an exact key)")
	cmd.Flags().StringVar(&f.expectedDNS, "expected-dns-name", "", "require this DNS name on the CA-pinned identity (needs --trusted-ca-file)")
}

func runAssetsProbe(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cl, err := newClient()
	if err != nil {
		return err
	}
	assetID, err := cl.ResolveAsset(ctx, args[0])
	if err != nil {
		return err
	}

	job, err := startProbe(ctx, cl, assetID, probeEndpointRevision)
	if err != nil {
		return err
	}
	obs, err := probeAndObserve(cmd, cl, assetID, job, probeWaitTimeout)
	if err != nil {
		return err
	}
	return renderObservation(cmd, obs)
}

func runAssetsIdentityList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cl, err := newClient()
	if err != nil {
		return err
	}
	assetID, err := cl.ResolveAsset(ctx, args[0])
	if err != nil {
		return err
	}
	anchors, err := listAnchors(ctx, cl, assetID)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(anchors))
	msgs := make([]proto.Message, 0, len(anchors))
	for _, a := range anchors {
		rows = append(rows, anchorRow(a))
		msgs = append(msgs, a)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{Headers: anchorHeaders, Rows: rows})
}

func runAssetsIdentityApprove(cmd *cobra.Command, args []string) error {
	// Validate the flag contract before touching the network.
	if err := identityFlagValues.validate(); err != nil {
		return err
	}
	// Refuse to hang on a prompt we cannot show.
	if identityFlagValues.wouldPrompt() && !stdinIsTTY() {
		return errors.New("refusing to prompt in a non-interactive context: pass --expected-fingerprint, --trusted-ca-file, or --auto-approve")
	}

	ctx := cmd.Context()
	cl, err := newClient()
	if err != nil {
		return err
	}
	assetID, err := cl.ResolveAsset(ctx, args[0])
	if err != nil {
		return err
	}

	obs, err := latestObservation(ctx, cl, assetID)
	if err != nil {
		return err
	}
	if obs == nil {
		return errors.New("no observation to approve; run `jumpgate assets probe` first")
	}

	anchors, err := decideAndApprove(cmd, cl, assetID, obs, identityFlagValues)
	if err != nil {
		return err
	}
	msgs := make([]proto.Message, 0, len(anchors))
	rows := make([][]string, 0, len(anchors))
	for _, a := range anchors {
		msgs = append(msgs, a)
		rows = append(rows, anchorRow(a))
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{Headers: anchorHeaders, Rows: rows})
}

func runAssetsIdentityRevoke(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cl, err := newClient()
	if err != nil {
		return err
	}
	assetID, err := cl.ResolveAsset(ctx, args[0])
	if err != nil {
		return err
	}
	anchorID := args[1]

	// The optimistic-concurrency check keys off the anchor's own endpoint
	// revision, so look it up rather than asking the operator to supply it.
	anchors, err := listAnchors(ctx, cl, assetID)
	if err != nil {
		return err
	}
	var target *targetidentityv1.TrustAnchor
	for _, a := range anchors {
		if a.GetId() == anchorID {
			target = a
			break
		}
	}
	if target == nil {
		return fmt.Errorf("trust anchor %q not found for this asset", anchorID)
	}

	req := connect.NewRequest(&targetidentityv1.RevokeTrustAnchorRequest{
		RequestId:                uuid.NewString(),
		AssetId:                  assetID,
		ExpectedEndpointRevision: target.GetEndpointRevision(),
		TrustAnchorId:            anchorID,
		Reason:                   revokeReason,
	})
	cl.Authorize(req)
	resp, err := cl.TargetIdentity().RevokeTrustAnchor(ctx, req)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "revoked trust anchor %s; verification status: %s\n", anchorID, statusName(resp.Msg.GetStatus()))
	return nil
}

// probeAndObserve waits for a started probe and returns its observation. It
// prints progress to stderr and, on timeout, makes clear the durable probe was
// not cancelled.
func probeAndObserve(cmd *cobra.Command, cl *wardenclient.Client, assetID string, job *targetidentityv1.ProbeJob, timeout time.Duration) (*targetidentityv1.Observation, error) {
	final, err := waitForProbe(cmd.Context(), cl, assetID, job.GetId(), timeout, cmd.ErrOrStderr())
	if err != nil {
		var to *probeTimeoutError
		if errors.As(err, &to) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "probe %s is durable and continues running server-side; it was not cancelled. Re-check later with `jumpgate assets identity`.\n", job.GetId())
		}
		return nil, err
	}
	if final.GetState() != targetidentityv1.ProbeState_PROBE_STATE_SUCCEEDED {
		return nil, fmt.Errorf("probe %s did not succeed (state %s): %s", job.GetId(), stateName(final.GetState()), final.GetFailureDetail())
	}
	obs, err := observationForProbe(cmd.Context(), cl, assetID, job.GetId())
	if err != nil {
		return nil, err
	}
	if obs == nil {
		return nil, fmt.Errorf("probe %s succeeded but produced no observation", job.GetId())
	}
	return obs, nil
}

// waitForProbe polls GetProbe until the probe reaches a terminal state or the
// (optional) timeout elapses, using context-aware exponential backoff capped at
// 2s. A terminal non-success state is returned as a job (not an error) so the
// caller can decide; a timeout is a typed probeTimeoutError.
func waitForProbe(ctx context.Context, cl *wardenclient.Client, assetID, probeID string, timeout time.Duration, progress io.Writer) (*targetidentityv1.ProbeJob, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	const maxBackoff = 2 * time.Second
	backoff := 200 * time.Millisecond
	for {
		req := connect.NewRequest(&targetidentityv1.GetProbeRequest{AssetId: assetID, ProbeId: probeID})
		cl.Authorize(req)
		resp, err := cl.TargetIdentity().GetProbe(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, &probeTimeoutError{probeID: probeID}
			}
			return nil, err
		}
		job := resp.Msg.GetProbe()
		switch job.GetState() {
		case targetidentityv1.ProbeState_PROBE_STATE_SUCCEEDED,
			targetidentityv1.ProbeState_PROBE_STATE_FAILED,
			targetidentityv1.ProbeState_PROBE_STATE_SUPERSEDED,
			targetidentityv1.ProbeState_PROBE_STATE_CANCELLED:
			return job, nil
		}
		_, _ = fmt.Fprintf(progress, "probe %s: %s...\n", probeID, stateName(job.GetState()))
		select {
		case <-ctx.Done():
			return nil, &probeTimeoutError{probeID: probeID}
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// decideAndApprove resolves the approval decision for obs and, unless declined,
// calls the appropriate approval RPC. It returns the resulting trust anchors
// (nil when the operator declines an interactive prompt).
func decideAndApprove(cmd *cobra.Command, cl *wardenclient.Client, assetID string, obs *targetidentityv1.Observation, f identityFlags) ([]*targetidentityv1.TrustAnchor, error) {
	rev := obs.GetEndpointRevision()
	switch {
	case f.expectFP != "":
		ev := evidenceByFingerprint(obs, f.expectFP)
		if ev == nil {
			return nil, fmt.Errorf("no observed identity matches expected fingerprint %q (observed: %s)", f.expectFP, strings.Join(observedFingerprints(obs), ", "))
		}
		return approveEvidence(cmd, cl, assetID, rev, obs.GetId(), []string{ev.GetId()}, targetidentityv1.TrustSource_TRUST_SOURCE_EXPECTED)

	case f.trustedCAFile != "":
		return approveCA(cmd, cl, assetID, rev, obs, f)

	case f.autoApprove:
		ids := evidenceIDs(obs)
		if len(ids) == 0 {
			return nil, errors.New("observation carries no evidence to approve")
		}
		return approveEvidence(cmd, cl, assetID, rev, obs.GetId(), ids, targetidentityv1.TrustSource_TRUST_SOURCE_TOFU)

	default:
		if !stdinIsTTY() {
			return nil, errors.New("refusing to prompt in a non-interactive context: pass --expected-fingerprint, --trusted-ca-file, or --auto-approve")
		}
		ok, err := promptApprove(cmd, obs)
		if err != nil {
			return nil, err
		}
		if !ok {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "not approved")
			return nil, nil
		}
		ids := evidenceIDs(obs)
		if len(ids) == 0 {
			return nil, errors.New("observation carries no evidence to approve")
		}
		return approveEvidence(cmd, cl, assetID, rev, obs.GetId(), ids, targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL)
	}
}

func approveEvidence(cmd *cobra.Command, cl *wardenclient.Client, assetID string, rev int64, obsID string, evidenceIDs []string, source targetidentityv1.TrustSource) ([]*targetidentityv1.TrustAnchor, error) {
	req := connect.NewRequest(&targetidentityv1.ApproveEvidenceRequest{
		RequestId:                uuid.NewString(),
		AssetId:                  assetID,
		ExpectedEndpointRevision: rev,
		ObservationId:            obsID,
		EvidenceIds:              evidenceIDs,
		Source:                   source,
	})
	cl.Authorize(req)
	resp, err := cl.TargetIdentity().ApproveEvidence(cmd.Context(), req)
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "approved %d trust anchor(s); verification status: %s\n", len(resp.Msg.GetTrustAnchors()), statusName(resp.Msg.GetStatus()))
	return resp.Msg.GetTrustAnchors(), nil
}

func approveCA(cmd *cobra.Command, cl *wardenclient.Client, assetID string, rev int64, obs *targetidentityv1.Observation, f identityFlags) ([]*targetidentityv1.TrustAnchor, error) {
	material, err := os.ReadFile(f.trustedCAFile) // #nosec G304 -- the CA file is the operator's chosen path
	if err != nil {
		return nil, fmt.Errorf("read trusted CA file: %w", err)
	}
	if len(material) == 0 {
		return nil, fmt.Errorf("trusted CA file %q is empty", f.trustedCAFile)
	}
	validated := validatedEvidence(obs)
	if validated == nil {
		return nil, errors.New("observation carries no evidence to bind the CA to")
	}

	var dnsNames []string
	if f.expectedDNS != "" {
		dnsNames = []string{f.expectedDNS}
	}
	req := connect.NewRequest(&targetidentityv1.ApproveCARequest{
		RequestId:                uuid.NewString(),
		AssetId:                  assetID,
		ExpectedEndpointRevision: rev,
		ObservationId:            obs.GetId(),
		ValidatedEvidenceId:      validated.GetId(),
		Kind:                     caAnchorKind(obs),
		PublicMaterial:           string(material),
		Source:                   targetidentityv1.TrustSource_TRUST_SOURCE_EXPECTED,
		RequiredDnsNames:         dnsNames,
	})
	cl.Authorize(req)
	resp, err := cl.TargetIdentity().ApproveCA(cmd.Context(), req)
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "approved CA trust anchor; verification status: %s\n", statusName(resp.Msg.GetStatus()))
	return []*targetidentityv1.TrustAnchor{resp.Msg.GetTrustAnchor()}, nil
}

func promptApprove(cmd *cobra.Command, obs *targetidentityv1.Observation) (bool, error) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Observed identity for endpoint revision %d:\n", obs.GetEndpointRevision())
	for _, e := range obs.GetEvidence() {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  %s %s %s\n", evKindName(e.GetKind()), e.GetAlgorithm(), e.GetSha256Fingerprint())
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Approve this observed identity? [y/N] ")
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false, nil // treat EOF with no input as the default (No)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// startProbe queues a probe and returns the created job.
func startProbe(ctx context.Context, cl *wardenclient.Client, assetID string, rev int64) (*targetidentityv1.ProbeJob, error) {
	req := connect.NewRequest(&targetidentityv1.StartProbeRequest{
		RequestId:                uuid.NewString(),
		AssetId:                  assetID,
		ExpectedEndpointRevision: rev,
	})
	cl.Authorize(req)
	resp, err := cl.TargetIdentity().StartProbe(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetProbe(), nil
}

func listAnchors(ctx context.Context, cl *wardenclient.Client, assetID string) ([]*targetidentityv1.TrustAnchor, error) {
	return collectPages(func(token string) ([]*targetidentityv1.TrustAnchor, string, error) {
		req := connect.NewRequest(&targetidentityv1.ListTrustAnchorsRequest{AssetId: assetID, PageSize: 100, PageToken: token})
		cl.Authorize(req)
		resp, err := cl.TargetIdentity().ListTrustAnchors(ctx, req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetTrustAnchors(), resp.Msg.GetNextPageToken(), nil
	})
}

// observationForProbe returns the observation produced by a specific probe.
func observationForProbe(ctx context.Context, cl *wardenclient.Client, assetID, probeID string) (*targetidentityv1.Observation, error) {
	obs, err := listObservations(ctx, cl, assetID)
	if err != nil {
		return nil, err
	}
	for _, o := range obs {
		if o.GetProbeId() == probeID {
			return o, nil
		}
	}
	return nil, nil
}

// latestObservation returns the most recently observed identity for an asset.
func latestObservation(ctx context.Context, cl *wardenclient.Client, assetID string) (*targetidentityv1.Observation, error) {
	obs, err := listObservations(ctx, cl, assetID)
	if err != nil {
		return nil, err
	}
	var latest *targetidentityv1.Observation
	for _, o := range obs {
		if latest == nil || o.GetObservedAtUnixMs() > latest.GetObservedAtUnixMs() {
			latest = o
		}
	}
	return latest, nil
}

func listObservations(ctx context.Context, cl *wardenclient.Client, assetID string) ([]*targetidentityv1.Observation, error) {
	return collectPages(func(token string) ([]*targetidentityv1.Observation, string, error) {
		req := connect.NewRequest(&targetidentityv1.ListObservationsRequest{AssetId: assetID, PageSize: 100, PageToken: token})
		cl.Authorize(req)
		resp, err := cl.TargetIdentity().ListObservations(ctx, req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetObservations(), resp.Msg.GetNextPageToken(), nil
	})
}

func renderObservation(cmd *cobra.Command, obs *targetidentityv1.Observation) error {
	rows := make([][]string, 0, len(obs.GetEvidence()))
	for _, e := range obs.GetEvidence() {
		rows = append(rows, evidenceRow(e))
	}
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, obs, &output.Table{Headers: evidenceHeaders, Rows: rows})
}

func evidenceByFingerprint(obs *targetidentityv1.Observation, fp string) *targetidentityv1.Evidence {
	want := strings.TrimSpace(fp)
	for _, e := range obs.GetEvidence() {
		if e.GetSha256Fingerprint() == want {
			return e
		}
	}
	return nil
}

func observedFingerprints(obs *targetidentityv1.Observation) []string {
	out := make([]string, 0, len(obs.GetEvidence()))
	for _, e := range obs.GetEvidence() {
		out = append(out, e.GetSha256Fingerprint())
	}
	return out
}

func evidenceIDs(obs *targetidentityv1.Observation) []string {
	out := make([]string, 0, len(obs.GetEvidence()))
	for _, e := range obs.GetEvidence() {
		out = append(out, e.GetId())
	}
	return out
}

// validatedEvidence picks the leaf evidence a CA approval binds to: the TLS leaf
// (or SSH host cert/key) presented by the target, falling back to the first item.
func validatedEvidence(obs *targetidentityv1.Observation) *targetidentityv1.Evidence {
	ev := obs.GetEvidence()
	for _, e := range ev {
		if e.GetKind() == targetidentityv1.EvidenceKind_EVIDENCE_KIND_TLS_LEAF {
			return e
		}
	}
	if len(ev) > 0 {
		return ev[0]
	}
	return nil
}

// caAnchorKind infers whether a --trusted-ca-file pins an SSH host CA or a TLS
// CA from the protocol of the observed evidence.
func caAnchorKind(obs *targetidentityv1.Observation) targetidentityv1.TrustAnchorKind {
	for _, e := range obs.GetEvidence() {
		switch e.GetKind() {
		case targetidentityv1.EvidenceKind_EVIDENCE_KIND_SSH_HOST_KEY,
			targetidentityv1.EvidenceKind_EVIDENCE_KIND_SSH_HOST_CERTIFICATE:
			return targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_SSH_HOST_CA
		}
	}
	return targetidentityv1.TrustAnchorKind_TRUST_ANCHOR_KIND_TLS_CA
}

var anchorHeaders = []string{"ID", "KIND", "ALGORITHM", "FINGERPRINT", "SOURCE", "REV", "STATE"}

func anchorRow(a *targetidentityv1.TrustAnchor) []string {
	state := "active"
	if a.GetRevokedAtUnixMs() != 0 {
		state = "revoked"
	}
	return []string{
		a.GetId(),
		anchorKindName(a.GetKind()),
		a.GetAlgorithm(),
		a.GetSha256Fingerprint(),
		sourceName(a.GetSource()),
		fmt.Sprintf("%d", a.GetEndpointRevision()),
		state,
	}
}

var evidenceHeaders = []string{"EVIDENCE ID", "KIND", "ALGORITHM", "FINGERPRINT"}

func evidenceRow(e *targetidentityv1.Evidence) []string {
	return []string{e.GetId(), evKindName(e.GetKind()), e.GetAlgorithm(), e.GetSha256Fingerprint()}
}

func stateName(s targetidentityv1.ProbeState) string {
	return strings.TrimPrefix(s.String(), "PROBE_STATE_")
}

func statusName(s targetidentityv1.VerificationStatus) string {
	return strings.TrimPrefix(s.String(), "VERIFICATION_STATUS_")
}

func anchorKindName(k targetidentityv1.TrustAnchorKind) string {
	return strings.TrimPrefix(k.String(), "TRUST_ANCHOR_KIND_")
}

func sourceName(s targetidentityv1.TrustSource) string {
	return strings.TrimPrefix(s.String(), "TRUST_SOURCE_")
}

func evKindName(k targetidentityv1.EvidenceKind) string {
	return strings.TrimPrefix(k.String(), "EVIDENCE_KIND_")
}
