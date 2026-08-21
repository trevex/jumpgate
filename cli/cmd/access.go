package cmd

import (
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

var requestHeaders = []string{"ID", "ROLE", "ASSET", "STATUS", "REASON"}

func requestRow(r *accessrequestv1.AccessRequest) []string {
	return []string{r.GetId(), r.GetRoleId(), r.GetAssetId(), r.GetStatus(), r.GetReason()}
}

var grantHeaders = []string{"ID", "ROLE", "ASSET", "ACTIVE", "EXPIRES"}

func grantRow(g *accessrequestv1.Grant) []string {
	return []string{g.GetId(), g.GetRoleId(), g.GetAssetId(), fmt.Sprintf("%t", g.GetActive()), g.GetExpiresAt()}
}

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Request and manage just-in-time access",
}

var (
	accessRequestRole     string
	accessRequestReason   string
	accessRequestDuration string
)

var accessRequestCmd = &cobra.Command{
	Use:   "request [<login>@]<asset>",
	Short: "Request just-in-time access to an asset",
	Args:  cobra.ExactArgs(1),
	RunE:  runAccessRequest,
}

var accessListPending bool

var accessListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your access requests (or pending approvals)",
	Args:  cobra.NoArgs,
	RunE:  runAccessList,
}

var accessApproveCmd = &cobra.Command{
	Use:   "approve <request-id>",
	Short: "Approve a pending access request",
	Args:  cobra.ExactArgs(1),
	RunE:  runAccessApprove,
}

var accessDenyCmd = &cobra.Command{
	Use:   "deny <request-id>",
	Short: "Deny a pending access request",
	Args:  cobra.ExactArgs(1),
	RunE:  runAccessDeny,
}

var accessGrantsCmd = &cobra.Command{
	Use:   "grants",
	Short: "List your active access grants",
	Args:  cobra.NoArgs,
	RunE:  runAccessGrants,
}

func init() {
	accessRequestCmd.Flags().StringVar(&accessRequestRole, "role", "", "role id or name (required)")
	accessRequestCmd.Flags().StringVar(&accessRequestReason, "reason", "", "reason for the request")
	accessRequestCmd.Flags().StringVar(&accessRequestDuration, "duration", "", "requested access duration (Go duration, e.g. 2h)")
	_ = accessRequestCmd.MarkFlagRequired("role")

	accessListCmd.Flags().BoolVar(&accessListPending, "pending-approvals", false, "list requests awaiting your approval instead of your own")

	accessCmd.AddCommand(accessRequestCmd)
	accessCmd.AddCommand(accessListCmd)
	accessCmd.AddCommand(accessApproveCmd)
	accessCmd.AddCommand(accessDenyCmd)
	accessCmd.AddCommand(accessGrantsCmd)
	rootCmd.AddCommand(accessCmd)
}

func runAccessRequest(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	// The target may carry a leading "<login>@" like `connect`; the request
	// scope is the asset.
	_, asset, err := parseTarget(args[0], "")
	if err != nil {
		return err
	}
	assetID, err := cl.ResolveAsset(cmd.Context(), asset) // uuid | DNS path; requester-capable
	if err != nil {
		return err
	}

	roleID := accessRequestRole
	if _, uerr := uuid.Parse(roleID); uerr != nil {
		// Resolve the role name against the caller's requestable set on this asset.
		areq := connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: assetID})
		cl.Authorize(areq)
		aresp, gerr := cl.Catalog().GetAssetAccess(cmd.Context(), areq)
		if gerr != nil {
			return gerr
		}
		roleID, err = matchRequestableRole(aresp.Msg.GetRequestableRoles(), accessRequestRole, asset)
		if err != nil {
			return err
		}
	}

	req := &accessrequestv1.RequestAccessRequest{
		RoleId:  roleID,
		AssetId: assetID,
		Reason:  accessRequestReason,
	}
	if accessRequestDuration != "" {
		d, err := time.ParseDuration(accessRequestDuration)
		if err != nil {
			return fmt.Errorf("invalid --duration %q: %w", accessRequestDuration, err)
		}
		req.DurationSeconds = int64(d.Seconds())
	}

	creq := connect.NewRequest(req)
	cl.Authorize(creq)
	resp, err := cl.AccessRequest().RequestAccess(cmd.Context(), creq)
	if err != nil {
		return err
	}

	r := resp.Msg.GetRequest()
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, r, &output.Table{
		Headers: requestHeaders,
		Rows:    [][]string{requestRow(r)},
	})
}

// matchRequestableRole finds exactly one role in refs matching ref by bare name or
// by the qualified "<name>.<folder-path>" form. Errors clearly on none/ambiguous.
func matchRequestableRole(refs []*catalogv1.RoleRef, ref, asset string) (string, error) {
	var hits []string
	for _, r := range refs {
		qualified := r.GetName()
		if r.GetFolderPath() != "" {
			qualified = r.GetName() + "." + r.GetFolderPath()
		}
		if ref == r.GetName() || ref == qualified {
			hits = append(hits, r.GetId())
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("role %q is not requestable on %s", ref, asset)
	default:
		return "", fmt.Errorf("role %q is ambiguous on %s; use <name>.<folder-path> or the role id", ref, asset)
	}
}

func runAccessList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	var requests []*accessrequestv1.AccessRequest
	var ferr error
	if accessListPending {
		requests, ferr = collectPages(func(token string) ([]*accessrequestv1.AccessRequest, string, error) {
			req := connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{PageSize: 100, PageToken: token})
			cl.Authorize(req)
			resp, err := cl.AccessRequest().ListPendingApprovals(cmd.Context(), req)
			if err != nil {
				return nil, "", err
			}
			return resp.Msg.GetRequests(), resp.Msg.GetNextPageToken(), nil
		})
	} else {
		requests, ferr = collectPages(func(token string) ([]*accessrequestv1.AccessRequest, string, error) {
			req := connect.NewRequest(&accessrequestv1.ListMyRequestsRequest{PageSize: 100, PageToken: token})
			cl.Authorize(req)
			resp, err := cl.AccessRequest().ListMyRequests(cmd.Context(), req)
			if err != nil {
				return nil, "", err
			}
			return resp.Msg.GetRequests(), resp.Msg.GetNextPageToken(), nil
		})
	}
	if ferr != nil {
		return ferr
	}

	rows := make([][]string, 0, len(requests))
	msgs := make([]proto.Message, 0, len(requests))
	for _, r := range requests {
		rows = append(rows, requestRow(r))
		msgs = append(msgs, r)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: requestHeaders,
		Rows:    rows,
	})
}

func runAccessApprove(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&accessrequestv1.ApproveRequestRequest{RequestId: args[0]})
	cl.Authorize(req)
	if _, err := cl.AccessRequest().ApproveRequest(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "approved request %s\n", args[0])
	return nil
}

func runAccessDeny(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&accessrequestv1.DenyRequestRequest{RequestId: args[0]})
	cl.Authorize(req)
	if _, err := cl.AccessRequest().DenyRequest(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "denied request %s\n", args[0])
	return nil
}

func runAccessGrants(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	grants, err := collectPages(func(token string) ([]*accessrequestv1.Grant, string, error) {
		req := connect.NewRequest(&accessrequestv1.ListMyGrantsRequest{PageSize: 100, PageToken: token})
		cl.Authorize(req)
		resp, err := cl.AccessRequest().ListMyGrants(cmd.Context(), req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetGrants(), resp.Msg.GetNextPageToken(), nil
	})
	if err != nil {
		return err
	}

	rows := make([][]string, 0, len(grants))
	msgs := make([]proto.Message, 0, len(grants))
	for _, g := range grants {
		rows = append(rows, grantRow(g))
		msgs = append(msgs, g)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: grantHeaders,
		Rows:    rows,
	})
}
