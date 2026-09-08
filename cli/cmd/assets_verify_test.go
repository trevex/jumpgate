package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	targetidentityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1"
)

// A stable folder UUID so resolveFolderID short-circuits (no ResolveFolder RPC).
const tiFolderID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

// resetVerifyFlags restores the package-global flag/TTY state the report and
// bulk-probe commands mutate, so slice/bool flags do not leak across tests.
func resetVerifyFlags() {
	flagOutput = "table"
	verifyReportFolder = ""
	probeAll = false
	probeAllFolder = ""
	probeAllYes = false
	probeEndpointRevision = 1
	stdinIsTTY = defaultStdinIsTTY
	rootCmd.SetIn(nil)
	for _, c := range []*cobra.Command{assetsProbeCmd, assetsVerifyReportCmd} {
		c.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
	}
}

// migAsset builds a catalog asset with a uuid-shaped id derived from n.
func migAsset(id, name, path string) *catalogv1.Asset {
	return &catalogv1.Asset{Id: id, Name: name, Path: path, Kind: "ssh"}
}

func activeAnchor() *targetidentityv1.TrustAnchor {
	return &targetidentityv1.TrustAnchor{Id: "anchor-ok", Sha256Fingerprint: "SHA256:ok", Source: targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL}
}

// legacyAnchor is a migration-sourced anchor carrying no usable material — the
// import could not derive a real key, so it can never verify.
func legacyAnchor() *targetidentityv1.TrustAnchor {
	return &targetidentityv1.TrustAnchor{Id: "anchor-legacy", Source: targetidentityv1.TrustSource_TRUST_SOURCE_MIGRATION}
}

// expiredAnchor is a non-revoked anchor whose expiry is in the past.
func expiredAnchor() *targetidentityv1.TrustAnchor {
	return &targetidentityv1.TrustAnchor{Id: "anchor-exp", Sha256Fingerprint: "SHA256:exp", Source: targetidentityv1.TrustSource_TRUST_SOURCE_MANUAL, ExpiresAtUnixMs: time.Now().Add(-time.Hour).UnixMilli()}
}

const (
	aVerified = "10000000-0000-0000-0000-000000000001"
	aPending  = "10000000-0000-0000-0000-000000000002"
	aLegacy   = "10000000-0000-0000-0000-000000000003"
	aChanged  = "10000000-0000-0000-0000-000000000004"
	aExpired  = "10000000-0000-0000-0000-000000000005"
)

// reportFixture wires five assets each landing on a distinct report status.
func reportFixture() *stubAssets {
	return &stubAssets{
		listed: []*catalogv1.Asset{
			migAsset(aVerified, "verified-box", "prod.verified-box"),
			migAsset(aPending, "pending-box", "prod.pending-box"),
			migAsset(aLegacy, "legacy-box", "prod.legacy-box"),
			migAsset(aChanged, "changed-box", "prod.changed-box"),
			migAsset(aExpired, "expired-box", "prod.expired-box"),
		},
		ti: &stubTargetIdentity{
			statusByAsset: map[string]targetidentityv1.VerificationStatus{
				aVerified: targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
				aPending:  targetidentityv1.VerificationStatus_VERIFICATION_STATUS_PENDING_VERIFICATION,
				aLegacy:   targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
				aChanged:  targetidentityv1.VerificationStatus_VERIFICATION_STATUS_IDENTITY_CHANGED,
				aExpired:  targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
			},
			anchorsByAsset: map[string][]*targetidentityv1.TrustAnchor{
				aVerified: {activeAnchor()},
				aPending:  nil,
				aLegacy:   {legacyAnchor()},
				aChanged:  {activeAnchor()},
				aExpired:  {expiredAnchor()},
			},
		},
	}
}

func setupMig(t *testing.T, s *stubAssets) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetVerifyFlags)
}

func TestVerifyReportRowsReflectStatus(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "verify-report", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}

	var got struct {
		Total  int            `json:"total"`
		Counts map[string]int `json:"counts"`
		Assets []struct {
			AssetID string `json:"asset_id"`
			Status  string `json:"status"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout not parseable JSON: %v\nstdout=%s", err, out.String())
	}
	if got.Total != 5 {
		t.Fatalf("total=%d, want 5", got.Total)
	}
	byAsset := map[string]string{}
	for _, r := range got.Assets {
		byAsset[r.AssetID] = r.Status
	}
	want := map[string]string{
		aVerified: "verified",
		aPending:  "pending",
		aLegacy:   "invalid-legacy-material",
		aChanged:  "identity_changed",
		aExpired:  "expired-anchor",
	}
	for id, w := range want {
		if byAsset[id] != w {
			t.Fatalf("asset %s status=%q, want %q", id, byAsset[id], w)
		}
	}
	// Counts tally the per-asset statuses.
	for _, w := range []string{"verified", "pending", "invalid-legacy-material", "identity_changed", "expired-anchor"} {
		if got.Counts[w] != 1 {
			t.Fatalf("counts[%q]=%d, want 1 (counts=%v)", w, got.Counts[w], got.Counts)
		}
	}
}

func TestVerifyReportJSONIsCleanDocument(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "verify-report", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	// stdout is exactly one JSON document (data → stdout, progress → stderr).
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\nstdout=%s", err, out.String())
	}
	if dec.More() {
		t.Fatalf("stdout carried trailing content after the JSON document: %s", out.String())
	}
}

func TestVerifyReportFolderScoping(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "verify-report", "--folder", tiFolderID, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	if s.gotListAssets == nil {
		t.Fatal("ListAssets was not called")
	}
	if s.gotListAssets.GetParent() != tiFolderID {
		t.Fatalf("ListAssets parent=%q, want the folder %q", s.gotListAssets.GetParent(), tiFolderID)
	}
	if !s.gotListAssets.GetCascade() {
		t.Fatal("the report must scan descendant folders (cascade)")
	}
}

func TestVerifyReportTable(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "verify-report"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	got := out.String()
	for _, w := range []string{"legacy-box", "invalid-legacy-material", "identity_changed", "expired-anchor"} {
		if !strings.Contains(got, w) {
			t.Fatalf("table missing %q:\n%s", w, got)
		}
	}
}

func TestProbeAllRequiresFolder(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "probe", "--all", "--yes"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("--all must require --folder")
	}
	if len(s.ti.startedAssets) != 0 {
		t.Fatalf("no probe must be queued without --folder, started=%v", s.ti.startedAssets)
	}
}

func TestProbeAllRefusesWithoutConfirmationNonTTY(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)
	// Non-interactive is the default under `go test`; no --yes given.

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "probe", "--all", "--folder", tiFolderID})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("bulk probe must refuse without --yes in a non-interactive context")
	}
	if len(s.ti.startedAssets) != 0 {
		t.Fatalf("nothing must be queued without confirmation, started=%v", s.ti.startedAssets)
	}
}

func TestProbeAllQueuesWithYes(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{"assets", "probe", "--all", "--folder", tiFolderID, "--yes"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	if len(s.ti.startedAssets) != 5 {
		t.Fatalf("expected a probe queued for each of 5 assets, started=%v", s.ti.startedAssets)
	}
	// Queue only: no approval RPC of any kind may fire.
	if s.ti.gotApproveEvidence != nil || s.ti.gotApproveCA != nil {
		t.Fatal("bulk probe must NEVER approve; it only queues probes")
	}
}

func TestProbeAllInteractiveConfirm(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)
	stdinIsTTY = func() bool { return true }

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetIn(strings.NewReader("y\n"))
	rootCmd.SetArgs([]string{"assets", "probe", "--all", "--folder", tiFolderID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}
	if len(s.ti.startedAssets) != 5 {
		t.Fatalf("a 'y' confirmation must queue all probes, started=%v", s.ti.startedAssets)
	}
}

func TestProbeAllInteractiveDeclineQueuesNothing(t *testing.T) {
	s := reportFixture()
	setupMig(t, s)
	stdinIsTTY = func() bool { return true }

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetIn(strings.NewReader("\n")) // bare Enter → default NO
	rootCmd.SetArgs([]string{"assets", "probe", "--all", "--folder", tiFolderID})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(s.ti.startedAssets) != 0 {
		t.Fatalf("a declined confirmation must queue nothing, started=%v", s.ti.startedAssets)
	}
}

// TestNoBulkApprovalPath is the correctness pin: no command or flag anywhere in
// the tree exposes a bulk-approval bypass. The single-asset `identity approve`
// --auto-approve is fine; a *bulk* approve (a folder-wide / --all approve, or a
// flag literally named to approve many) must not exist.
func TestNoBulkApprovalPath(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		// No command may both scope a whole folder/all AND approve.
		use := strings.ToLower(c.Use)
		if strings.Contains(use, "approve") && (strings.Contains(use, "all") || strings.Contains(use, "folder") || strings.Contains(use, "bulk")) {
			t.Fatalf("found a bulk-approval command: %q", c.CommandPath())
		}
		hasAll := c.Flags().Lookup("all") != nil
		c.Flags().VisitAll(func(f *pflag.Flag) {
			name := strings.ToLower(f.Name)
			if name == "approve-all" || strings.Contains(name, "approveall") {
				t.Fatalf("found a bulk-approval flag %q on %q", f.Name, c.CommandPath())
			}
			// A command that scopes --all must not also carry any approve flag.
			if hasAll && strings.Contains(name, "approve") {
				t.Fatalf("command %q scopes --all and also exposes approve flag %q", c.CommandPath(), f.Name)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}
