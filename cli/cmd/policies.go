package cmd

import (
	"fmt"
	"strconv"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
)

var policyHeaders = []string{"ID", "REQUEST-ROLE", "SCOPE", "APPROVALS", "REQUESTER-ROLE", "APPROVER-ROLE"}

func policyRow(p *accessv1.RequestPolicy) []string {
	return []string{
		p.GetId(),
		p.GetRoleId(),
		policyScope(p),
		strconv.Itoa(int(p.GetRequiredApprovals())),
		p.GetRequesterRoleId(),
		p.GetApproverRoleId(),
	}
}

// policyScope renders the single scope of a policy as a "kind:id" pair. Both
// empty means the policy is a role-level default.
func policyScope(p *accessv1.RequestPolicy) string {
	switch {
	case p.GetScopeAssetId() != "":
		return "asset:" + p.GetScopeAssetId()
	case p.GetScopeFolderId() != "":
		return "folder:" + p.GetScopeFolderId()
	default:
		return "role-default"
	}
}

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "Manage request policies",
}

var (
	policiesCreateRequestRole   string
	policiesCreateAsset         string
	policiesCreateFolder        string
	policiesCreateApproverRole  string
	policiesCreateRequesterRole string
	policiesCreateMinApprovals  int32
)

var policiesCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a request policy for a role at a scope",
	Args:  cobra.NoArgs,
	RunE:  runPoliciesCreate,
}

var policiesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List request policies",
	Args:  cobra.NoArgs,
	RunE:  runPoliciesList,
}

var (
	policiesAddSubjectKind  string
	policiesAddSubjectUser  string
	policiesAddSubjectGroup string
)

var policiesAddSubjectCmd = &cobra.Command{
	Use:   "add-subject <policy-id>",
	Short: "Add an approver or requester subject to a policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runPoliciesAddSubject,
}

func init() {
	policiesCreateCmd.Flags().StringVar(&policiesCreateRequestRole, "request-role", "", "role id or name the policy makes requestable (required)")
	policiesCreateCmd.Flags().StringVar(&policiesCreateAsset, "asset", "", "scope asset id or name")
	policiesCreateCmd.Flags().StringVar(&policiesCreateFolder, "folder", "", "scope folder id or name")
	policiesCreateCmd.Flags().StringVar(&policiesCreateApproverRole, "approver-role", "", "role id or name whose holders may approve")
	policiesCreateCmd.Flags().StringVar(&policiesCreateRequesterRole, "requester-role", "", "role id or name whose holders may request")
	policiesCreateCmd.Flags().Int32Var(&policiesCreateMinApprovals, "min-approvals", 0, "number of approvals required")
	_ = policiesCreateCmd.MarkFlagRequired("request-role")

	policiesAddSubjectCmd.Flags().StringVar(&policiesAddSubjectKind, "kind", "", "subject kind: approver or requester (required)")
	policiesAddSubjectCmd.Flags().StringVar(&policiesAddSubjectUser, "user", "", "subject user id or email")
	policiesAddSubjectCmd.Flags().StringVar(&policiesAddSubjectGroup, "group", "", "subject group id or name")
	_ = policiesAddSubjectCmd.MarkFlagRequired("kind")

	policiesCmd.AddCommand(policiesCreateCmd)
	policiesCmd.AddCommand(policiesListCmd)
	policiesCmd.AddCommand(policiesAddSubjectCmd)
	rootCmd.AddCommand(policiesCmd)
}

func runPoliciesCreate(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	// Exactly one scope. A policy targets a single asset or folder (or, when
	// neither is given, would be a role-level default); warden rejects two
	// scopes, but we fail early with a clearer message.
	if (policiesCreateAsset != "") == (policiesCreateFolder != "") {
		return fmt.Errorf("exactly one of --asset or --folder is required")
	}

	roleID, err := resolveRoleID(cmd.Context(), cl, policiesCreateRequestRole)
	if err != nil {
		return err
	}

	req := &accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		RequiredApprovals: policiesCreateMinApprovals,
	}

	if policiesCreateAsset != "" {
		assetID, err := cl.ResolveAsset(cmd.Context(), policiesCreateAsset)
		if err != nil {
			return err
		}
		req.ScopeAssetId = assetID
	} else {
		folderID, err := resolveFolderID(cmd.Context(), cl, policiesCreateFolder)
		if err != nil {
			return err
		}
		req.ScopeFolderId = folderID
	}

	if policiesCreateApproverRole != "" {
		approverID, err := resolveRoleID(cmd.Context(), cl, policiesCreateApproverRole)
		if err != nil {
			return err
		}
		req.ApproverRoleId = approverID
	}
	if policiesCreateRequesterRole != "" {
		requesterID, err := resolveRoleID(cmd.Context(), cl, policiesCreateRequesterRole)
		if err != nil {
			return err
		}
		req.RequesterRoleId = requesterID
	}

	creq := connect.NewRequest(req)
	cl.Authorize(creq)
	resp, err := cl.Access().CreateRequestPolicy(cmd.Context(), creq)
	if err != nil {
		return err
	}

	p := resp.Msg.GetPolicy()
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, p, &output.Table{
		Headers: policyHeaders,
		Rows:    [][]string{policyRow(p)},
	})
}

func runPoliciesList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&accessv1.ListRequestPoliciesRequest{})
	cl.Authorize(req)
	resp, err := cl.Access().ListRequestPolicies(cmd.Context(), req)
	if err != nil {
		return err
	}

	policies := resp.Msg.GetPolicies()
	rows := make([][]string, 0, len(policies))
	msgs := make([]proto.Message, 0, len(policies))
	for _, p := range policies {
		rows = append(rows, policyRow(p))
		msgs = append(msgs, p)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: policyHeaders,
		Rows:    rows,
	})
}

func runPoliciesAddSubject(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	switch policiesAddSubjectKind {
	case "approver", "requester":
	default:
		return fmt.Errorf("--kind must be approver or requester, got %q", policiesAddSubjectKind)
	}

	// Exactly one subject. A subject entry names a single user or group.
	if (policiesAddSubjectUser != "") == (policiesAddSubjectGroup != "") {
		return fmt.Errorf("exactly one of --user or --group is required")
	}

	req := &accessv1.AddPolicySubjectRequest{
		PolicyId: args[0],
		Kind:     policiesAddSubjectKind,
	}

	if policiesAddSubjectUser != "" {
		userID, err := resolveUserID(cmd.Context(), cl, policiesAddSubjectUser)
		if err != nil {
			return err
		}
		req.SubjectUserId = userID
	} else {
		groupID, err := resolveGroupID(cmd.Context(), cl, policiesAddSubjectGroup)
		if err != nil {
			return err
		}
		req.SubjectGroupId = groupID
	}

	creq := connect.NewRequest(req)
	cl.Authorize(creq)
	resp, err := cl.Access().AddPolicySubject(cmd.Context(), creq)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "added %s subject %s to policy %s\n",
		policiesAddSubjectKind, resp.Msg.GetId(), args[0])
	return nil
}
