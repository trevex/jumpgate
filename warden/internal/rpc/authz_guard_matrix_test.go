package rpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	recordingv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1/recordingv1connect"
	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// guardClients bundles a Connect client per service, all pointed at one test server.
type guardClients struct {
	identity identityv1connect.IdentityServiceClient
	catalog  catalogv1connect.CatalogServiceClient
	access   accessv1connect.AccessServiceClient
	areq     accessrequestv1connect.AccessRequestServiceClient
	vault    vaultv1connect.VaultServiceClient
	rec      recordingv1connect.RecordingServiceClient
	session  sessionv1connect.SessionServiceClient
}

func newGuardClients(url string) guardClients {
	h := http.DefaultClient
	return guardClients{
		identity: identityv1connect.NewIdentityServiceClient(h, url),
		catalog:  catalogv1connect.NewCatalogServiceClient(h, url),
		access:   accessv1connect.NewAccessServiceClient(h, url),
		areq:     accessrequestv1connect.NewAccessRequestServiceClient(h, url),
		vault:    vaultv1connect.NewVaultServiceClient(h, url),
		rec:      recordingv1connect.NewRecordingServiceClient(h, url),
		session:  sessionv1connect.NewSessionServiceClient(h, url),
	}
}

// guardFixture holds one existing object of every referenceable kind, so a guard
// case can invoke a real RPC with well-formed arguments (reaching the capability
// check rather than tripping arg-validation or a pre-guard NotFound).
type guardFixture struct {
	folderID     string
	assetID      string
	assetPath    string
	roleID       string // folder-scoped role
	srcRoleID    string
	bindingID    string
	policyID     string
	policyName   string
	subjectID    string // a request_policy_subject id (for RemovePolicySubject)
	secretID     string
	groupID      string
	targetUserID string
	pendingReq   string // a pending access_request owned by targetUser
	grantID      string // an active grant for targetUser
	roleGrantID  string // a role_grants edge id
	recSession   string // a completed recording of the asset
	clientSSHKey []byte
}

// buildGuardFixture provisions the fixture as the bootstrap admin (via the real
// RPCs) plus a few rows the API doesn't create directly (grants, requests,
// recordings, role-grant edges), seeded through the DB layer. The referenced
// "victim" objects (the grant/request subject, the recording user, the
// ExplainRole target) belong to a user OTHER than the capless caller, so no case
// accidentally exercises a self-service path.
func buildGuardFixture(t *testing.T, url, adminTok string, pool *pgxpool.Pool) guardFixture {
	t.Helper()
	ctx := context.Background()
	cl := newGuardClients(url)
	f := guardFixture{}

	victim, err := cl.identity.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "victim@x", DisplayName: "Victim", Password: "victimpass123",
	}), adminTok))
	if err != nil {
		t.Fatalf("fixture victim: %v", err)
	}
	f.targetUserID = victim.Msg.User.Id
	targetUserID := uuid.MustParse(victim.Msg.User.Id)

	folder, err := cl.catalog.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "gf"}), adminTok))
	if err != nil {
		t.Fatalf("fixture folder: %v", err)
	}
	f.folderID = folder.Msg.Folder.Id

	asset, err := cl.catalog.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: f.folderID, Name: "ga", Kind: "ssh",
	}), adminTok))
	if err != nil {
		t.Fatalf("fixture asset: %v", err)
	}
	f.assetID = asset.Msg.Asset.Id
	f.assetPath = asset.Msg.Asset.Path

	role, err := cl.access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "grole", FolderId: f.folderID, Capabilities: []string{"ssh:login:deploy"},
	}), adminTok))
	if err != nil {
		t.Fatalf("fixture role: %v", err)
	}
	f.roleID = role.Msg.Role.Id

	srcRole, err := cl.access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "gsrc", FolderId: f.folderID, Capabilities: []string{"ssh:login:deploy"},
	}), adminTok))
	if err != nil {
		t.Fatalf("fixture src role: %v", err)
	}
	f.srcRoleID = srcRole.Msg.Role.Id

	group, err := cl.identity.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "ggroup"}), adminTok))
	if err != nil {
		t.Fatalf("fixture group: %v", err)
	}
	f.groupID = group.Msg.Group.Id

	binding, err := cl.access.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: f.roleID, ScopeAssetId: f.assetID, SubjectGroupId: f.groupID,
	}), adminTok))
	if err != nil {
		t.Fatalf("fixture binding: %v", err)
	}
	f.bindingID = binding.Msg.Id

	f.policyName = "gpolicy"
	policy, err := cl.access.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId: f.roleID, ScopeAssetId: f.assetID, RequiredApprovals: 1, Name: f.policyName,
	}), adminTok))
	if err != nil {
		t.Fatalf("fixture policy: %v", err)
	}
	f.policyID = policy.Msg.Policy.Id

	if _, err := cl.access.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{
		PolicyId: f.policyID, Kind: "requester", SubjectGroupId: f.groupID,
	}), adminTok)); err != nil {
		t.Fatalf("fixture add subject: %v", err)
	}
	subs, err := cl.access.ListPolicySubjects(ctx, withToken(connect.NewRequest(&accessv1.ListPolicySubjectsRequest{PolicyId: f.policyID}), adminTok))
	if err != nil || len(subs.Msg.Subjects) == 0 {
		t.Fatalf("fixture list subjects: %v", err)
	}
	f.subjectID = subs.Msg.Subjects[0].Id

	if _, err := cl.vault.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{
		AssetId: f.assetID, Name: "gsecret", Value: []byte("s3cr3t"),
	}), adminTok)); err != nil {
		t.Fatalf("fixture secret: %v", err)
	}
	secs, err := cl.vault.ListAssetSecrets(ctx, withToken(connect.NewRequest(&vaultv1.ListAssetSecretsRequest{AssetId: f.assetID}), adminTok))
	if err != nil || len(secs.Msg.Secrets) == 0 {
		t.Fatalf("fixture list secrets: %v", err)
	}
	f.secretID = secs.Msg.Secrets[0].Id

	// Rows the API does not create directly: a pending request, an active grant,
	// a role-grant edge, and a completed recording — seeded via the DB layer.
	q := gen.New(pool)
	assetUUID := uuid.MustParse(f.assetID)
	roleUUID := uuid.MustParse(f.roleID)
	hour := pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true}

	pending, err := q.CreateAccessRequest(ctx, gen.CreateAccessRequestParams{
		RequesterUserID: targetUserID, RoleID: roleUUID, AssetID: assetUUID,
		Reason: "guard-seed", RequestedDuration: hour, RequiredApprovals: 1, GrantedDuration: hour, Status: "pending",
	})
	if err != nil {
		t.Fatalf("fixture pending request: %v", err)
	}
	f.pendingReq = pending.ID.String()

	granted, err := q.CreateAccessRequest(ctx, gen.CreateAccessRequestParams{
		RequesterUserID: targetUserID, RoleID: roleUUID, AssetID: assetUUID,
		Reason: "guard-seed", RequestedDuration: hour, RequiredApprovals: 0, GrantedDuration: hour, Status: "granted",
	})
	if err != nil {
		t.Fatalf("fixture granted request: %v", err)
	}
	grant, err := q.CreateAccessGrant(ctx, gen.CreateAccessGrantParams{
		RequestID: granted.ID, RoleID: roleUUID, ScopeAssetID: assetUUID, SubjectUserID: targetUserID,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("fixture grant: %v", err)
	}
	f.grantID = grant.ID.String()

	rg, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{
		RoleID: roleUUID, SourceRoleID: uuid.MustParse(f.srcRoleID), Via: "same_object",
	})
	if err != nil {
		t.Fatalf("fixture role grant: %v", err)
	}
	f.roleGrantID = rg.ID.String()

	f.recSession = seedRecordingRow(t, pool, targetUserID, assetUUID).String()

	// A valid client SSH public key (authorized_keys line) for CreateSession.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("fixture ssh key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("fixture ssh pub: %v", err)
	}
	f.clientSSHKey = ssh.MarshalAuthorizedKey(sshPub)
	return f
}

// TestAuthzGuardMatrix is the completeness/regression guard for the management
// API: a fully authenticated but capability-less user must be DENIED on every
// management RPC. "Denied" is the specific code the endpoint is designed to
// return — PermissionDenied for capability gates, NotFound for the
// existence-hiding endpoints (so denial never leaks that the object exists).
//
// A user with NO capabilities holds a valid token but no roles, so this pins the
// invariant "authenticated ≠ authorized" across the whole surface. If a new RPC
// is added without a guard, or a guard is removed, a case here flips to OK and
// fails.
func TestAuthzGuardMatrix(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedCapUser(t, pool, "capless@x", "caplesspass", `[]`)
	adminTok := adminToken(t, url)
	tok := authClient(t, url, "capless@x", "caplesspass")
	ctx := context.Background()

	f := buildGuardFixture(t, url, adminTok, pool)
	cl := newGuardClients(url)

	const (
		PD = connect.CodePermissionDenied
		NF = connect.CodeNotFound
	)

	cases := []struct {
		name string
		want connect.Code
		call func() error
	}{
		// ---- IdentityService ----
		{"Identity.CreateUser", PD, func() error {
			_, err := cl.identity.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "z@x", DisplayName: "Z", Password: "password123"}), tok))
			return err
		}},
		{"Identity.GetUser", PD, func() error {
			_, err := cl.identity.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: f.targetUserID}), tok))
			return err
		}},
		{"Identity.ResolveUser", PD, func() error {
			_, err := cl.identity.ResolveUser(ctx, withToken(connect.NewRequest(&identityv1.ResolveUserRequest{Email: "admin@x"}), tok))
			return err
		}},
		{"Identity.ListUsers", PD, func() error {
			_, err := cl.identity.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 10}), tok))
			return err
		}},
		{"Identity.CreateGroup", PD, func() error {
			_, err := cl.identity.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "zgroup"}), tok))
			return err
		}},
		{"Identity.ResolveGroup", NF, func() error {
			_, err := cl.identity.ResolveGroup(ctx, withToken(connect.NewRequest(&identityv1.ResolveGroupRequest{Name: "ggroup"}), tok))
			return err
		}},
		{"Identity.AddUserToGroup", PD, func() error {
			_, err := cl.identity.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{GroupId: f.groupID, UserId: f.targetUserID}), tok))
			return err
		}},
		{"Identity.AddGroupToGroup", PD, func() error {
			_, err := cl.identity.AddGroupToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddGroupToGroupRequest{GroupId: f.groupID, MemberGroupId: f.groupID}), tok))
			return err
		}},
		{"Identity.RemoveUserFromGroup", PD, func() error {
			_, err := cl.identity.RemoveUserFromGroup(ctx, withToken(connect.NewRequest(&identityv1.RemoveUserFromGroupRequest{GroupId: f.groupID, UserId: f.targetUserID}), tok))
			return err
		}},
		{"Identity.ListGroupMembers", PD, func() error {
			_, err := cl.identity.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: f.groupID}), tok))
			return err
		}},
		{"Identity.DeactivateUser", PD, func() error {
			_, err := cl.identity.DeactivateUser(ctx, withToken(connect.NewRequest(&identityv1.DeactivateUserRequest{UserId: f.targetUserID}), tok))
			return err
		}},
		{"Identity.ReactivateUser", PD, func() error {
			_, err := cl.identity.ReactivateUser(ctx, withToken(connect.NewRequest(&identityv1.ReactivateUserRequest{UserId: f.targetUserID}), tok))
			return err
		}},
		{"Identity.DeleteUser", PD, func() error {
			_, err := cl.identity.DeleteUser(ctx, withToken(connect.NewRequest(&identityv1.DeleteUserRequest{UserId: f.targetUserID}), tok))
			return err
		}},
		{"Identity.DeleteGroup", PD, func() error {
			_, err := cl.identity.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{GroupId: f.groupID}), tok))
			return err
		}},

		// ---- CatalogService ----
		{"Catalog.CreateFolder", PD, func() error {
			_, err := cl.catalog.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "zf"}), tok))
			return err
		}},
		// ListFolders/ListAssets are intentionally NOT in this deny matrix: they are
		// not capability-gated but visibility-filtered — a capless user gets an empty
		// (non-error) result, not a denial. That is pinned in
		// TestAuthzSelfServiceListsAreNotDenied.
		{"Catalog.CreateAsset", PD, func() error {
			_, err := cl.catalog.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.folderID, Name: "za", Kind: "ssh"}), tok))
			return err
		}},
		{"Catalog.GetAsset", PD, func() error {
			_, err := cl.catalog.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: f.assetID}), tok))
			return err
		}},
		{"Catalog.ResolveAsset", NF, func() error {
			_, err := cl.catalog.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: f.assetPath}), tok))
			return err
		}},
		{"Catalog.ResolveFolder", NF, func() error {
			_, err := cl.catalog.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "gf"}), tok))
			return err
		}},
		{"Catalog.GetAssetAccess", NF, func() error {
			_, err := cl.catalog.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: f.assetID}), tok))
			return err
		}},
		{"Catalog.GetFolderAccess", NF, func() error {
			_, err := cl.catalog.GetFolderAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetFolderAccessRequest{FolderId: f.folderID}), tok))
			return err
		}},

		// ---- AccessService ----
		{"Access.CreateRole", PD, func() error {
			_, err := cl.access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "zrole", Capabilities: []string{"ssh:login:deploy"}}), tok))
			return err
		}},
		{"Access.ListRoles", PD, func() error {
			_, err := cl.access.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 10}), tok))
			return err
		}},
		{"Access.GetRole", PD, func() error {
			_, err := cl.access.GetRole(ctx, withToken(connect.NewRequest(&accessv1.GetRoleRequest{Id: f.roleID}), tok))
			return err
		}},
		{"Access.ResolveRole", PD, func() error {
			_, err := cl.access.ResolveRole(ctx, withToken(connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: "grole.gf"}), tok))
			return err
		}},
		{"Access.AddRoleGrant", PD, func() error {
			_, err := cl.access.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{RoleId: f.roleID, SourceRoleId: f.srcRoleID, Via: "same_object"}), tok))
			return err
		}},
		{"Access.RemoveRoleGrant", PD, func() error {
			_, err := cl.access.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.RemoveRoleGrantRequest{Id: f.roleGrantID}), tok))
			return err
		}},
		{"Access.ListRoleGrants", PD, func() error {
			_, err := cl.access.ListRoleGrants(ctx, withToken(connect.NewRequest(&accessv1.ListRoleGrantsRequest{RoleId: f.roleID}), tok))
			return err
		}},
		{"Access.CreateRoleBinding", PD, func() error {
			_, err := cl.access.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{RoleId: f.roleID, ScopeAssetId: f.assetID, SubjectGroupId: f.groupID}), tok))
			return err
		}},
		{"Access.DeleteRoleBinding", PD, func() error {
			_, err := cl.access.DeleteRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleBindingRequest{Id: f.bindingID}), tok))
			return err
		}},
		{"Access.ListRoleBindings", PD, func() error {
			_, err := cl.access.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{RoleId: f.roleID}), tok))
			return err
		}},
		{"Access.CreateRequestPolicy", PD, func() error {
			_, err := cl.access.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{RoleId: f.roleID, ScopeAssetId: f.assetID, RequiredApprovals: 1, Name: "zpol"}), tok))
			return err
		}},
		{"Access.UpdateRequestPolicy", PD, func() error {
			_, err := cl.access.UpdateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.UpdateRequestPolicyRequest{Id: f.policyID, RequiredApprovals: 2}), tok))
			return err
		}},
		{"Access.DeleteRequestPolicy", PD, func() error {
			_, err := cl.access.DeleteRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.DeleteRequestPolicyRequest{Id: f.policyID}), tok))
			return err
		}},
		{"Access.ListRequestPolicies", PD, func() error {
			_, err := cl.access.ListRequestPolicies(ctx, withToken(connect.NewRequest(&accessv1.ListRequestPoliciesRequest{RoleId: f.roleID}), tok))
			return err
		}},
		{"Access.ResolvePolicy", PD, func() error {
			_, err := cl.access.ResolvePolicy(ctx, withToken(connect.NewRequest(&accessv1.ResolvePolicyRequest{Name: f.policyName, AssetId: f.assetID}), tok))
			return err
		}},
		{"Access.AddPolicySubject", PD, func() error {
			_, err := cl.access.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{PolicyId: f.policyID, Kind: "approver", SubjectGroupId: f.groupID}), tok))
			return err
		}},
		{"Access.RemovePolicySubject", PD, func() error {
			_, err := cl.access.RemovePolicySubject(ctx, withToken(connect.NewRequest(&accessv1.RemovePolicySubjectRequest{Id: f.subjectID}), tok))
			return err
		}},
		{"Access.ListPolicySubjects", PD, func() error {
			_, err := cl.access.ListPolicySubjects(ctx, withToken(connect.NewRequest(&accessv1.ListPolicySubjectsRequest{PolicyId: f.policyID}), tok))
			return err
		}},
		{"Access.ExplainRole(cross-user)", PD, func() error {
			_, err := cl.access.ExplainRole(ctx, withToken(connect.NewRequest(&accessv1.ExplainRoleRequest{UserId: f.targetUserID, RoleId: f.roleID, AssetId: f.assetID}), tok))
			return err
		}},

		// ---- AccessRequestService ----
		{"AccessRequest.ResolveApproval", PD, func() error {
			_, err := cl.areq.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{RoleId: f.roleID, AssetId: f.assetID}), tok))
			return err
		}},
		{"AccessRequest.RequestAccess(ineligible)", NF, func() error {
			_, err := cl.areq.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{RoleId: f.roleID, AssetId: f.assetID, DurationSeconds: 3600, Reason: "x"}), tok))
			return err
		}},
		{"AccessRequest.ApproveRequest(non-approver)", PD, func() error {
			_, err := cl.areq.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{RequestId: f.pendingReq}), tok))
			return err
		}},
		{"AccessRequest.DenyRequest(non-approver)", PD, func() error {
			_, err := cl.areq.DenyRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.DenyRequestRequest{RequestId: f.pendingReq}), tok))
			return err
		}},
		{"AccessRequest.CancelRequest(non-requester)", PD, func() error {
			_, err := cl.areq.CancelRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.CancelRequestRequest{RequestId: f.pendingReq}), tok))
			return err
		}},
		{"AccessRequest.RevokeGrant(non-subject)", PD, func() error {
			_, err := cl.areq.RevokeGrant(ctx, withToken(connect.NewRequest(&accessrequestv1.RevokeGrantRequest{GrantId: f.grantID}), tok))
			return err
		}},
		{"AccessRequest.ListGrants", PD, func() error {
			_, err := cl.areq.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{}), tok))
			return err
		}},

		// ---- VaultService ----
		{"Vault.InitCA", PD, func() error {
			_, err := cl.vault.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: "ssh"}), tok))
			return err
		}},
		{"Vault.GetCAPublic", PD, func() error {
			_, err := cl.vault.GetCAPublic(ctx, withToken(connect.NewRequest(&vaultv1.GetCAPublicRequest{Kind: "ssh"}), tok))
			return err
		}},
		{"Vault.InitMeshCA", PD, func() error {
			_, err := cl.vault.InitMeshCA(ctx, withToken(connect.NewRequest(&vaultv1.InitMeshCARequest{}), tok))
			return err
		}},
		{"Vault.InitSessionKey", PD, func() error {
			_, err := cl.vault.InitSessionKey(ctx, withToken(connect.NewRequest(&vaultv1.InitSessionKeyRequest{}), tok))
			return err
		}},
		{"Vault.SetAssetSecret", PD, func() error {
			_, err := cl.vault.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: f.assetID, Name: "z", Value: []byte("v")}), tok))
			return err
		}},
		{"Vault.DeleteAssetSecret", PD, func() error {
			_, err := cl.vault.DeleteAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.DeleteAssetSecretRequest{Id: f.secretID}), tok))
			return err
		}},
		{"Vault.ListAssetSecrets", PD, func() error {
			_, err := cl.vault.ListAssetSecrets(ctx, withToken(connect.NewRequest(&vaultv1.ListAssetSecretsRequest{AssetId: f.assetID}), tok))
			return err
		}},

		// ---- RecordingService ----
		{"Recording.ListRecordings", PD, func() error {
			_, err := cl.rec.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{PageSize: 10}), tok))
			return err
		}},
		{"Recording.GetRecording", PD, func() error {
			_, err := cl.rec.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: f.recSession}), tok))
			return err
		}},
		{"Recording.GetRecordingDownload", PD, func() error {
			_, err := cl.rec.GetRecordingDownload(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: f.recSession}), tok))
			return err
		}},

		// ---- SessionService ----
		{"Session.CreateSession(no access)", NF, func() error {
			_, err := cl.session.CreateSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateSessionRequest{AssetId: f.assetID, ClientSshPublicKey: f.clientSSHKey}), tok))
			return err
		}},
	}

	for _, tc := range cases {
		err := tc.call()
		got := connect.CodeOf(err)
		if err == nil {
			t.Errorf("%s: capless call SUCCEEDED, want denial %v", tc.name, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: capless code = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAuthzSelfServiceListsAreNotDenied pins the complement of the deny matrix:
// the self-service and visibility-scoped list endpoints must NOT deny a capless
// user — they return the caller's own (empty) view. A capless user therefore sees
// an empty catalog, no groups, no requests, and no grants, rather than an error.
func TestAuthzSelfServiceListsAreNotDenied(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedCapUser(t, pool, "capless@x", "caplesspass", `[]`)
	tok := authClient(t, url, "capless@x", "caplesspass")
	ctx := context.Background()
	cl := newGuardClients(url)

	// ListAssets is visibility-filtered, not cap-gated: a capless user browsing the
	// root catalog gets an empty (non-error) result rather than a denial.
	visible, err := cl.catalog.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Cascade: true}), tok))
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(visible.Msg.Assets) != 0 {
		t.Errorf("capless ListAssets = %d assets, want 0", len(visible.Msg.Assets))
	}

	// ListFolders is likewise visibility-filtered: a capless user browsing root
	// gets an empty (non-error) result, not a denial.
	visFolders, err := cl.catalog.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{Cascade: true}), tok))
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if len(visFolders.Msg.Folders) != 0 {
		t.Errorf("capless ListFolders = %d folders, want 0", len(visFolders.Msg.Folders))
	}

	groups, err := cl.identity.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 10}), tok))
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups.Msg.Groups) != 0 {
		t.Errorf("capless ListGroups = %d groups, want 0", len(groups.Msg.Groups))
	}

	reqs, err := cl.areq.ListMyRequests(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyRequestsRequest{}), tok))
	if err != nil {
		t.Fatalf("ListMyRequests: %v", err)
	}
	if len(reqs.Msg.Requests) != 0 {
		t.Errorf("capless ListMyRequests = %d, want 0", len(reqs.Msg.Requests))
	}

	pend, err := cl.areq.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{}), tok))
	if err != nil {
		t.Fatalf("ListPendingApprovals: %v", err)
	}
	if len(pend.Msg.Requests) != 0 {
		t.Errorf("capless ListPendingApprovals = %d, want 0", len(pend.Msg.Requests))
	}

	grants, err := cl.areq.ListMyGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyGrantsRequest{}), tok))
	if err != nil {
		t.Fatalf("ListMyGrants: %v", err)
	}
	if len(grants.Msg.Grants) != 0 {
		t.Errorf("capless ListMyGrants = %d, want 0", len(grants.Msg.Grants))
	}
}
