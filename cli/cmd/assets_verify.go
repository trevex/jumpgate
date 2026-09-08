package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	"github.com/trevex/jumpgate/cli/internal/output"
	"github.com/trevex/jumpgate/cli/internal/wardenclient"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	targetidentityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/targetidentity/v1"
)

// Migration tooling: a read-only fleet-wide verification report and a bounded
// bulk probe. Neither can approve — approval stays a per-asset, per-identity
// operator decision (`assets identity approve`). There is deliberately NO
// bulk-approval path.

var (
	verifyReportFolder string

	probeAll       bool
	probeAllFolder string
	probeAllYes    bool
)

var assetsVerifyReportCmd = &cobra.Command{
	Use:   "verify-report",
	Short: "Report each asset's target-identity verification status across the catalog",
	Long: "Scan the catalog (or a --folder subtree) and print, per asset, its " +
		"target-identity verification status plus a rollup of counts. Read-only: it " +
		"queues nothing and approves nothing. Data goes to stdout (a clean document " +
		"under `-o json`); nothing else is written there.",
	Args: cobra.NoArgs,
	RunE: runAssetsVerifyReport,
}

func init() {
	assetsVerifyReportCmd.Flags().StringVar(&verifyReportFolder, "folder", "", "scope the report to this folder subtree (id or path); default is the whole catalog")

	// `assets probe` gains a bounded bulk mode. The flags live here (migration
	// tooling); the single-asset path stays in target_identity.go. probeArgs and
	// the dispatcher below fold the two modes onto one command.
	assetsProbeCmd.Flags().BoolVar(&probeAll, "all", false, "queue an identity probe for every asset in --folder (queues only; never approves)")
	assetsProbeCmd.Flags().StringVar(&probeAllFolder, "folder", "", "folder subtree to probe (id or path); required with --all")
	assetsProbeCmd.Flags().BoolVar(&probeAllYes, "yes", false, "skip the confirmation prompt (required with --all in a non-interactive context)")
	assetsProbeCmd.Args = probeArgs
	assetsProbeCmd.RunE = runAssetsProbeDispatch

	assetsCmd.AddCommand(assetsVerifyReportCmd)
}

// probeArgs accepts no positional asset in --all mode (a whole folder is the
// target) and exactly one otherwise.
func probeArgs(cmd *cobra.Command, args []string) error {
	if probeAll {
		if len(args) != 0 {
			return errors.New("--all probes a whole folder; do not also pass an asset argument")
		}
		return nil
	}
	return cobra.ExactArgs(1)(cmd, args)
}

func runAssetsProbeDispatch(cmd *cobra.Command, args []string) error {
	if probeAll {
		return runAssetsProbeAll(cmd)
	}
	return runAssetsProbe(cmd, args)
}

// ── verify-report ───────────────────────────────────────────────────────────

type verifyReportRow struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
}

type verifyReport struct {
	Folder string            `json:"folder,omitempty"`
	Total  int               `json:"total"`
	Counts map[string]int    `json:"counts"`
	Assets []verifyReportRow `json:"assets"`
}

func runAssetsVerifyReport(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	cl, err := newClient()
	if err != nil {
		return err
	}

	parent := ""
	if verifyReportFolder != "" {
		parent, err = resolveFolderID(ctx, cl, verifyReportFolder)
		if err != nil {
			return err
		}
	}

	assets, err := listAssetsUnder(ctx, cl, parent)
	if err != nil {
		return err
	}

	now := time.Now()
	report := verifyReport{Folder: verifyReportFolder, Total: len(assets), Counts: map[string]int{}}
	for _, a := range assets {
		status, err := getVerificationStatus(ctx, cl, a.GetId())
		if err != nil {
			return err
		}
		anchors, err := listAnchors(ctx, cl, a.GetId())
		if err != nil {
			return err
		}
		label := reportStatus(status, anchors, now)
		report.Counts[label]++
		report.Assets = append(report.Assets, verifyReportRow{
			AssetID: a.GetId(), Name: a.GetName(), Path: a.GetPath(), Kind: a.GetKind(), Status: label,
		})
	}

	// In table mode the counts rollup is human output and belongs on stdout above
	// the rows. In json mode nothing extra is written so stdout stays one document.
	if flagOutput == "table" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d asset(s); %s\n\n", report.Total, formatCounts(report.Counts))
	}

	rows := make([][]string, 0, len(report.Assets))
	for _, r := range report.Assets {
		rows = append(rows, []string{r.Name, r.Path, r.Kind, r.Status})
	}
	return output.Render(cmd.OutOrStdout(), flagOutput, report, &output.Table{
		Headers: []string{"NAME", "PATH", "KIND", "STATUS"},
		Rows:    rows,
	})
}

// reportStatus maps an asset's server verification status plus its trust anchors
// to a single actionable label. Security-critical states win; legacy-migration
// concerns derived from the anchors surface the migration work still outstanding.
func reportStatus(vs targetidentityv1.VerificationStatus, anchors []*targetidentityv1.TrustAnchor, now time.Time) string {
	if vs == targetidentityv1.VerificationStatus_VERIFICATION_STATUS_IDENTITY_CHANGED {
		return "identity_changed"
	}
	if hasInvalidMigrationAnchor(anchors) {
		return "invalid-legacy-material"
	}
	if vs == targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFICATION_EXPIRED || hasExpiredActiveAnchor(anchors, now) {
		return "expired-anchor"
	}
	switch vs {
	case targetidentityv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED:
		return "verified"
	case targetidentityv1.VerificationStatus_VERIFICATION_STATUS_PENDING_VERIFICATION:
		return "pending"
	case targetidentityv1.VerificationStatus_VERIFICATION_STATUS_AWAITING_APPROVAL:
		return "awaiting_approval"
	case targetidentityv1.VerificationStatus_VERIFICATION_STATUS_PROBE_FAILED:
		return "probe_failed"
	default:
		return "unknown"
	}
}

// hasInvalidMigrationAnchor reports whether any active anchor was imported by the
// legacy migration but carries no usable material — a placeholder that can never
// verify and must be re-probed + re-approved.
func hasInvalidMigrationAnchor(anchors []*targetidentityv1.TrustAnchor) bool {
	for _, a := range anchors {
		if a.GetRevokedAtUnixMs() != 0 {
			continue
		}
		if a.GetSource() == targetidentityv1.TrustSource_TRUST_SOURCE_MIGRATION &&
			a.GetSha256Fingerprint() == "" && a.GetPublicMaterial() == "" {
			return true
		}
	}
	return false
}

// hasExpiredActiveAnchor reports whether a non-revoked anchor has passed its
// expiry.
func hasExpiredActiveAnchor(anchors []*targetidentityv1.TrustAnchor, now time.Time) bool {
	cutoff := now.UnixMilli()
	for _, a := range anchors {
		if a.GetRevokedAtUnixMs() != 0 {
			continue
		}
		if exp := a.GetExpiresAtUnixMs(); exp != 0 && exp < cutoff {
			return true
		}
	}
	return false
}

func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "no assets"
	}
	// Stable, human-friendly ordering: worst-first.
	order := []string{"identity_changed", "invalid-legacy-material", "expired-anchor", "probe_failed", "awaiting_approval", "pending", "verified"}
	parts := make([]string, 0, len(counts))
	seen := map[string]bool{}
	for _, k := range order {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, n))
			seen[k] = true
		}
	}
	for k, n := range counts {
		if !seen[k] {
			parts = append(parts, fmt.Sprintf("%s=%d", k, n))
		}
	}
	return strings.Join(parts, " ")
}

// ── probe --all (bounded, queue-only) ────────────────────────────────────────

type bulkProbeResult struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	ProbeID string `json:"probe_id,omitempty"`
	Error   string `json:"error,omitempty"`
}

type bulkProbeReport struct {
	Folder  string            `json:"folder"`
	Total   int               `json:"total"`
	Queued  int               `json:"queued"`
	Results []bulkProbeResult `json:"results"`
}

func runAssetsProbeAll(cmd *cobra.Command) error {
	if probeAllFolder == "" {
		return errors.New("--all requires --folder <ref>")
	}

	ctx := cmd.Context()
	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(ctx, cl, probeAllFolder)
	if err != nil {
		return err
	}
	assets, err := listAssetsUnder(ctx, cl, folderID)
	if err != nil {
		return err
	}
	if len(assets) == 0 {
		return fmt.Errorf("no assets found in folder %q", probeAllFolder)
	}

	// Confirmation gate. Interactive: prompt. Non-interactive: require --yes.
	if !probeAllYes {
		if !stdinIsTTY() {
			return errors.New("refusing to queue bulk probes without confirmation: pass --yes in a non-interactive context")
		}
		ok, err := confirmBulkProbe(cmd, probeAllFolder, len(assets))
		if err != nil {
			return err
		}
		if !ok {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "aborted; nothing queued")
			return nil
		}
	}

	// Queue only — never approve. Each StartProbe failure is recorded and the
	// batch continues so one unreachable asset does not stall the migration.
	report := bulkProbeReport{Folder: probeAllFolder, Total: len(assets)}
	var failures int
	for _, a := range assets {
		res := bulkProbeResult{AssetID: a.GetId(), Name: a.GetName(), Path: a.GetPath()}
		job, err := startProbe(ctx, cl, a.GetId(), probeEndpointRevision)
		if err != nil {
			res.Error = err.Error()
			failures++
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "asset %s: probe not queued: %v\n", a.GetName(), err)
		} else {
			res.ProbeID = job.GetId()
			report.Queued++
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "asset %s: queued probe %s\n", a.GetName(), job.GetId())
		}
		report.Results = append(report.Results, res)
	}

	rows := make([][]string, 0, len(report.Results))
	for _, r := range report.Results {
		state := r.ProbeID
		if r.Error != "" {
			state = "ERROR: " + r.Error
		}
		rows = append(rows, []string{r.Name, r.Path, state})
	}
	if err := output.Render(cmd.OutOrStdout(), flagOutput, report, &output.Table{
		Headers: []string{"NAME", "PATH", "PROBE"},
		Rows:    rows,
	}); err != nil {
		return err
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d probes could not be queued", failures, len(assets))
	}
	return nil
}

func confirmBulkProbe(cmd *cobra.Command, folder string, n int) (bool, error) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Queue identity probes for %d asset(s) in folder %q? This approves nothing. [y/N] ", n, folder)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false, nil // EOF with no input → default NO
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// ── shared helpers ───────────────────────────────────────────────────────────

// listAssetsUnder lists every asset in the parent subtree (cascade). An empty
// parent scans the whole visible catalog.
func listAssetsUnder(ctx context.Context, cl *wardenclient.Client, parent string) ([]*catalogv1.Asset, error) {
	return collectPages(func(token string) ([]*catalogv1.Asset, string, error) {
		req := connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: parent, Cascade: true, PageSize: 100, PageToken: token})
		cl.Authorize(req)
		resp, err := cl.Catalog().ListAssets(ctx, req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetAssets(), resp.Msg.GetNextPageToken(), nil
	})
}

func getVerificationStatus(ctx context.Context, cl *wardenclient.Client, assetID string) (targetidentityv1.VerificationStatus, error) {
	req := connect.NewRequest(&targetidentityv1.GetVerificationStatusRequest{AssetId: assetID})
	cl.Authorize(req)
	resp, err := cl.TargetIdentity().GetVerificationStatus(ctx, req)
	if err != nil {
		return targetidentityv1.VerificationStatus_VERIFICATION_STATUS_UNSPECIFIED, err
	}
	return resp.Msg.GetStatus(), nil
}
