package catalog

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	gossh "golang.org/x/crypto/ssh"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Handler adapts the catalog Service to the generated CatalogServiceHandler
// interface: it extracts the caller from context, validates + parses proto, applies
// the coarse capability gate for gate-first methods (entangled cap/visibility checks
// stay in the service, which takes the caller explicitly), calls one service method,
// and maps the domain result back to proto.
type Handler struct {
	svc   *Service
	guard apiguard.Guard
}

// NewHandler constructs the catalog transport Handler over svc and guard.
func NewHandler(svc *Service, guard apiguard.Guard) *Handler {
	return &Handler{svc: svc, guard: guard}
}

// caller extracts the authenticated user's id from ctx. In real requests the auth
// interceptor guarantees a user; an in-process caller without one is Unauthenticated.
func caller(ctx context.Context) (uuid.UUID, error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return uuid.Nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return u.ID, nil
}

// ── proto mapping ────────────────────────────────────────────────────────────

func toFolderMsg(f sqlc.Folder) *catalogv1.Folder {
	return &catalogv1.Folder{Id: f.ID.String(), Name: f.Name, ParentId: pgconv.UUIDString(f.ParentID)}
}

func folderMsg(res FolderResult) *catalogv1.Folder {
	m := toFolderMsg(res.Folder)
	m.Path = res.Path
	return m
}

func toAssetMsg(a sqlc.Asset) *catalogv1.Asset {
	return &catalogv1.Asset{Id: a.ID.String(), FolderId: a.FolderID.String(), Name: a.Name, Kind: a.Kind}
}

// toAssetMsgWithSSHConfig builds an Asset carrying its typed SSH config.
func toAssetMsgWithSSHConfig(a sqlc.Asset, cfg sqlc.SshAssetConfig, logins []sqlc.SshAssetLogin) *catalogv1.Asset {
	msg := toAssetMsg(a)
	out := make([]*catalogv1.SSHLogin, 0, len(logins))
	for _, l := range logins {
		out = append(out, &catalogv1.SSHLogin{Login: l.Login, Kind: l.Kind, SecretId: pgconv.UUIDString(l.SecretID)})
	}
	msg.Config = &catalogv1.Asset_Ssh{Ssh: &catalogv1.SSHConfig{
		Logins: out, HostPublicKey: cfg.HostPublicKey, TargetAddress: cfg.TargetAddress,
	}}
	return msg
}

// toAssetMsgWithPGConfig builds an Asset carrying its typed Postgres config.
func toAssetMsgWithPGConfig(a sqlc.Asset, cfg sqlc.PostgresAssetConfig, logins []sqlc.PostgresAssetLogin) *catalogv1.Asset {
	msg := toAssetMsg(a)
	out := make([]*catalogv1.PostgresLogin, 0, len(logins))
	for _, l := range logins {
		out = append(out, &catalogv1.PostgresLogin{Role: l.Role, Kind: l.Kind, SecretId: pgconv.UUIDString(l.SecretID)})
	}
	msg.Config = &catalogv1.Asset_Postgres{Postgres: &catalogv1.PostgresConfig{
		Logins: out, TargetAddress: cfg.TargetAddress, TargetServerCa: cfg.TargetServerCa, DefaultDatabase: cfg.DefaultDatabase,
	}}
	return msg
}

// assetMsg renders an AssetWithConfig: with typed config when present (by kind),
// else the bare asset. Path is copied from the domain result.
func assetMsg(res AssetWithConfig) *catalogv1.Asset {
	var m *catalogv1.Asset
	switch {
	case res.Config != nil:
		m = toAssetMsgWithSSHConfig(res.Asset, *res.Config, res.Logins)
	case res.PGConfig != nil:
		m = toAssetMsgWithPGConfig(res.Asset, *res.PGConfig, res.PGLogins)
	default:
		m = toAssetMsg(res.Asset)
	}
	m.Path = res.Path
	return m
}

// toRoleMsg renders a browse role row as an access-domain Role message.
func toRoleMsg(row RoleRow) *accessv1.Role {
	m := &accessv1.Role{
		Id:           row.Role.ID.String(),
		Name:         row.Role.Name,
		Capabilities: row.Caps,
		FolderId:     pgconv.UUIDString(row.Role.FolderID),
		FolderPath:   row.FolderPath,
	}
	return m
}

// toGroupMsg renders a browse group row as an identity-domain Group message.
func toGroupMsg(row GroupRow) *identityv1.Group {
	return &identityv1.Group{
		Id:         row.Group.ID.String(),
		Name:       row.Group.Name,
		FolderId:   pgconv.UUIDString(row.Group.FolderID),
		FolderPath: row.FolderPath,
	}
}

func toRoleRefMsg(r RoleRef) *catalogv1.RoleRef {
	return &catalogv1.RoleRef{Id: r.ID, Name: r.Name, FolderPath: r.FolderPath}
}

func toRoleRefMsgs(refs []RoleRef) []*catalogv1.RoleRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*catalogv1.RoleRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, toRoleRefMsg(r))
	}
	return out
}

// validateSSHConfigInput checks the parts protovalidate can't: an optional
// host_public_key must be a parseable authorized_keys line, and login names must be
// unique within the config (a duplicate would silently collapse under the
// (asset_id, login) upsert conflict).
func validateSSHConfigInput(in *catalogv1.SSHConfigInput) error {
	if in.GetHostPublicKey() != "" {
		if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(in.GetHostPublicKey())); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad host_public_key"))
		}
	}
	seen := make(map[string]struct{}, len(in.GetLogins()))
	for _, l := range in.GetLogins() {
		if _, dup := seen[l.GetLogin()]; dup {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate login "+l.GetLogin()))
		}
		seen[l.GetLogin()] = struct{}{}
	}
	return nil
}

// toDomainSSHConfig converts a wire SSHConfigInput into the proto-free domain form,
// deriving each login's kind from its auth oneof arm and its secret source from the
// SecretAuth oneof.
func toDomainSSHConfig(in *catalogv1.SSHConfigInput) (SSHConfigInput, error) {
	out := SSHConfigInput{HostPublicKey: in.GetHostPublicKey(), TargetAddress: in.GetTargetAddress()}
	for _, l := range in.GetLogins() {
		li := SSHLoginInput{Login: l.GetLogin()}
		switch a := l.GetAuth().(type) {
		case *catalogv1.SSHLoginInput_Ca:
			li.Kind = "ca"
		case *catalogv1.SSHLoginInput_Password:
			li.Kind = "password"
			src, err := toSecretSource(a.Password, l.GetLogin())
			if err != nil {
				return SSHConfigInput{}, err
			}
			li.Secret = src
		case *catalogv1.SSHLoginInput_Key:
			li.Kind = "key"
			src, err := toSecretSource(a.Key, l.GetLogin())
			if err != nil {
				return SSHConfigInput{}, err
			}
			li.Secret = src
		default:
			return SSHConfigInput{}, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+l.GetLogin()+": auth kind required"))
		}
		out.Logins = append(out.Logins, li)
	}
	return out, nil
}

func toSecretSource(sa *catalogv1.SecretAuth, login string) (*SecretSource, error) {
	switch src := sa.GetSource().(type) {
	case *catalogv1.SecretAuth_NewValue:
		return &SecretSource{Kind: "new", NewValue: src.NewValue}, nil
	case *catalogv1.SecretAuth_ExistingSecretId:
		return &SecretSource{Kind: "existing", ExistingSecretID: src.ExistingSecretId}, nil
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("login "+login+": secret source required"))
	}
}

// validatePostgresConfigInput checks the parts protovalidate can't: target_address
// must be present, an optional target_server_ca must be PEM-decodable, and role
// names must be unique within the config (a duplicate would collapse under the
// (asset_id, role) upsert conflict).
func validatePostgresConfigInput(in *catalogv1.PostgresConfigInput) error {
	if in.GetTargetAddress() == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("target_address required"))
	}
	if ca := in.GetTargetServerCa(); ca != "" {
		if block, _ := pem.Decode([]byte(ca)); block == nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad target_server_ca"))
		}
	}
	seen := make(map[string]struct{}, len(in.GetLogins()))
	for _, l := range in.GetLogins() {
		if _, dup := seen[l.GetRole()]; dup {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate role "+l.GetRole()))
		}
		seen[l.GetRole()] = struct{}{}
	}
	return nil
}

// toDomainPostgresConfig converts a wire PostgresConfigInput into the proto-free
// domain form, deriving each login's kind from its auth oneof arm.
func toDomainPostgresConfig(in *catalogv1.PostgresConfigInput) (PostgresConfigInput, error) {
	out := PostgresConfigInput{
		TargetAddress:   in.GetTargetAddress(),
		TargetServerCA:  in.GetTargetServerCa(),
		DefaultDatabase: in.GetDefaultDatabase(),
	}
	for _, l := range in.GetLogins() {
		li := PostgresLoginInput{Role: l.GetRole()}
		switch a := l.GetAuth().(type) {
		case *catalogv1.PostgresLoginInput_Mtls:
			li.Kind = "mtls"
		case *catalogv1.PostgresLoginInput_Password:
			li.Kind = "password"
			src, err := toSecretSource(a.Password, l.GetRole())
			if err != nil {
				return PostgresConfigInput{}, err
			}
			li.Secret = src
		default:
			return PostgresConfigInput{}, connect.NewError(connect.CodeInvalidArgument, errors.New("role "+l.GetRole()+": auth kind required"))
		}
		out.Logins = append(out.Logins, li)
	}
	return out, nil
}

// toAssetConfigInput converts a create/update config oneof (SSH, Postgres, or
// Kubernetes) into the kind-tagged domain union, running each kind's non-proto
// validation.
func toAssetConfigInput(ssh *catalogv1.SSHConfigInput, pg *catalogv1.PostgresConfigInput, k8s *catalogv1.KubernetesConfigInput) (AssetConfigInput, error) {
	switch {
	case ssh != nil:
		if err := validateSSHConfigInput(ssh); err != nil {
			return AssetConfigInput{}, err
		}
		in, err := toDomainSSHConfig(ssh)
		if err != nil {
			return AssetConfigInput{}, err
		}
		return AssetConfigInput{Kind: "ssh", SSH: &in}, nil
	case pg != nil:
		if err := validatePostgresConfigInput(pg); err != nil {
			return AssetConfigInput{}, err
		}
		in, err := toDomainPostgresConfig(pg)
		if err != nil {
			return AssetConfigInput{}, err
		}
		return AssetConfigInput{Kind: "postgres", Postgres: &in}, nil
	case k8s != nil:
		return AssetConfigInput{Kind: "k8s", Kubernetes: true}, nil
	default:
		return AssetConfigInput{}, connect.NewError(connect.CodeInvalidArgument, errors.New("config required"))
	}
}

// ── folders ──────────────────────────────────────────────────────────────────

// CreateFolder gates on catalog:folder:create then delegates to the service.
func (h *Handler) CreateFolder(ctx context.Context, req *connect.Request[catalogv1.CreateFolderRequest]) (*connect.Response[catalogv1.CreateFolderResponse], error) {
	var parent pgtype.UUID
	if req.Msg.ParentId != "" {
		pid, err := uuid.Parse(req.Msg.ParentId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad parent_id"))
		}
		parent = pgconv.UUID(pid)
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, authz.FolderCreateCap, apiguard.ScopeOfFolderID(parent)); err != nil {
		return nil, err
	}
	res, err := h.svc.CreateFolder(ctx, parent, strings.ToLower(req.Msg.Name))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.CreateFolderResponse{Folder: folderMsg(res)}), nil
}

// ListFolders returns the caller's visible folder page.
func (h *Handler) ListFolders(ctx context.Context, req *connect.Request[catalogv1.ListFoldersRequest]) (*connect.Response[catalogv1.ListFoldersResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListFolders(ctx, c, req.Msg.Parent, req.Msg.Cascade, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &catalogv1.ListFoldersResponse{NextPageToken: next}
	for _, r := range rows {
		m := toFolderMsg(r.Folder)
		m.Path = r.Path
		m.Governed = r.Governed
		out.Folders = append(out.Folders, m)
	}
	return connect.NewResponse(out), nil
}

// ResolveFolder maps a uuid/dotted path to a folder id (existence-hidden).
func (h *Handler) ResolveFolder(ctx context.Context, req *connect.Request[catalogv1.ResolveFolderRequest]) (*connect.Response[catalogv1.ResolveFolderResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.ResolveFolder(ctx, c, req.Msg.Ref)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.ResolveFolderResponse{FolderId: res.ID, Path: res.Path}), nil
}

// DeleteFolder removes an empty folder (blocks-if-referenced).
func (h *Handler) DeleteFolder(ctx context.Context, req *connect.Request[catalogv1.DeleteFolderRequest]) (*connect.Response[catalogv1.DeleteFolderResponse], error) {
	id, err := uuid.Parse(req.Msg.GetFolderId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid folder_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteFolder(ctx, c, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.DeleteFolderResponse{}), nil
}

// UpdateFolder renames and/or reparents a folder.
func (h *Handler) UpdateFolder(ctx context.Context, req *connect.Request[catalogv1.UpdateFolderRequest]) (*connect.Response[catalogv1.UpdateFolderResponse], error) {
	id, err := uuid.Parse(req.Msg.GetFolderId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid folder_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.UpdateFolder(ctx, c, id, UpdateFolderInput{Name: req.Msg.Name, ParentID: req.Msg.ParentId})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.UpdateFolderResponse{Folder: folderMsg(res)}), nil
}

// ── assets ───────────────────────────────────────────────────────────────────

// CreateAsset gates, validates + converts the SSH config, then delegates to the service.
func (h *Handler) CreateAsset(ctx context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	fid, err := uuid.Parse(req.Msg.GetFolderId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "catalog:asset:create", authz.FolderScope(fid)); err != nil {
		return nil, err
	}
	in, err := toAssetConfigInput(req.Msg.GetSsh(), req.Msg.GetPostgres(), req.Msg.GetKubernetes())
	if err != nil {
		return nil, err
	}
	res, err := h.svc.CreateAsset(ctx, fid, strings.ToLower(req.Msg.GetName()), in)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: assetMsg(res)}), nil
}

// GetAsset returns an asset with its typed config.
func (h *Handler) GetAsset(ctx context.Context, req *connect.Request[catalogv1.GetAssetRequest]) (*connect.Response[catalogv1.GetAssetResponse], error) {
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireReadCap(ctx, c, authz.AssetReadCap, authz.AssetScope(id)); err != nil {
		return nil, err
	}
	res, err := h.svc.GetAsset(ctx, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.GetAssetResponse{Asset: assetMsg(res)}), nil
}

// UpdateAssetConfig gates, validates + converts the SSH config, then delegates to the service.
func (h *Handler) UpdateAssetConfig(ctx context.Context, req *connect.Request[catalogv1.UpdateAssetConfigRequest]) (*connect.Response[catalogv1.UpdateAssetConfigResponse], error) {
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "catalog:asset:update", authz.AssetScope(assetID)); err != nil {
		return nil, err
	}
	in, err := toAssetConfigInput(req.Msg.GetSsh(), req.Msg.GetPostgres(), nil)
	if err != nil {
		return nil, err
	}
	if err := h.svc.UpdateAssetConfig(ctx, assetID, in); err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.UpdateAssetConfigResponse{}), nil
}

// ListAssets returns the caller's visible asset page.
func (h *Handler) ListAssets(ctx context.Context, req *connect.Request[catalogv1.ListAssetsRequest]) (*connect.Response[catalogv1.ListAssetsResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListAssets(ctx, c, req.Msg.Parent, req.Msg.Cascade, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &catalogv1.ListAssetsResponse{NextPageToken: next}
	for _, r := range rows {
		m := toAssetMsg(r.Asset)
		m.Path = r.Path
		out.Assets = append(out.Assets, m)
	}
	return connect.NewResponse(out), nil
}

// ResolveAsset maps a uuid/dotted path to a reachable asset id (existence-hidden).
func (h *Handler) ResolveAsset(ctx context.Context, req *connect.Request[catalogv1.ResolveAssetRequest]) (*connect.Response[catalogv1.ResolveAssetResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.ResolveAsset(ctx, c, req.Msg.Ref)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.ResolveAssetResponse{AssetId: res.ID, Path: res.Path, Kind: res.Kind}), nil
}

// DeleteAsset removes an asset (session teardown + DB FK cascade).
func (h *Handler) DeleteAsset(ctx context.Context, req *connect.Request[catalogv1.DeleteAssetRequest]) (*connect.Response[catalogv1.DeleteAssetResponse], error) {
	id, err := uuid.Parse(req.Msg.GetAssetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteAsset(ctx, c, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.DeleteAssetResponse{}), nil
}

// UpdateAsset renames and/or moves an asset.
func (h *Handler) UpdateAsset(ctx context.Context, req *connect.Request[catalogv1.UpdateAssetRequest]) (*connect.Response[catalogv1.UpdateAssetResponse], error) {
	id, err := uuid.Parse(req.Msg.GetAssetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.UpdateAsset(ctx, c, id, UpdateAssetInput{Name: req.Msg.Name, FolderID: req.Msg.FolderId})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.UpdateAssetResponse{Asset: assetMsg(res)}), nil
}

// ── browse / access / display / search ─────────────────────────────────────────

// GetAssetDisplay returns an asset's decision context without secret material.
func (h *Handler) GetAssetDisplay(ctx context.Context, req *connect.Request[catalogv1.GetAssetDisplayRequest]) (*connect.Response[catalogv1.GetAssetDisplayResponse], error) {
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.GetAssetDisplay(ctx, c, id)
	if err != nil {
		return nil, err
	}
	disp := &catalogv1.AssetDisplay{
		Id:         res.Asset.ID.String(),
		FolderId:   res.Asset.FolderID.String(),
		Name:       res.Asset.Name,
		Kind:       res.Asset.Kind,
		FolderPath: res.FolderPath,
		Path:       res.Path,
	}
	if res.Config != nil {
		ssh := &catalogv1.SSHConfigDisplay{
			HostPublicKey: res.Config.HostPublicKey,
			TargetAddress: res.Config.TargetAddress,
		}
		for _, l := range res.Logins {
			// Copy ONLY login + kind — never a secret id; SSHLoginDisplay has no such field.
			ssh.Logins = append(ssh.Logins, &catalogv1.SSHLoginDisplay{Login: l.Login, Kind: l.Kind})
		}
		disp.Config = &catalogv1.AssetDisplay_Ssh{Ssh: ssh}
	}
	if res.PGConfig != nil {
		pg := &catalogv1.PostgresConfigDisplay{
			TargetAddress:   res.PGConfig.TargetAddress,
			TargetServerCa:  res.PGConfig.TargetServerCa,
			DefaultDatabase: res.PGConfig.DefaultDatabase,
		}
		for _, l := range res.PGLogins {
			// Copy ONLY role + kind — never a secret id.
			pg.Logins = append(pg.Logins, &catalogv1.PostgresLoginDisplay{Role: l.Role, Kind: l.Kind})
		}
		disp.Config = &catalogv1.AssetDisplay_Postgres{Postgres: pg}
	}
	return connect.NewResponse(&catalogv1.GetAssetDisplayResponse{Asset: disp}), nil
}

// GetAssetAccess returns the caller's roles and capabilities on one asset.
func (h *Handler) GetAssetAccess(ctx context.Context, req *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
	}
	acc, err := h.svc.GetAssetAccess(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.GetAssetAccessResponse{
		ActiveRoleIds:          acc.ActiveRoleIDs,
		RequestableRoleIds:     acc.RequestableRoleIDs,
		ActiveRoles:            toRoleRefMsgs(acc.ActiveRoles),
		RequestableRoles:       toRoleRefMsgs(acc.RequestableRoles),
		Capabilities:           acc.Capabilities,
		ManagementCapabilities: acc.ManagementCapabilities,
		EntitledLogins:         acc.EntitledLogins,
	}), nil
}

// GetFolderAccess returns the caller's management capabilities on one folder.
func (h *Handler) GetFolderAccess(ctx context.Context, req *connect.Request[catalogv1.GetFolderAccessRequest]) (*connect.Response[catalogv1.GetFolderAccessResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	caps, err := h.svc.GetFolderAccess(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&catalogv1.GetFolderAccessResponse{Capabilities: caps}), nil
}

// ListFolderContents returns a bounded per-kind slice of a folder's visible children.
func (h *Handler) ListFolderContents(ctx context.Context, req *connect.Request[catalogv1.ListFolderContentsRequest]) (*connect.Response[catalogv1.ListFolderContentsResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	fc, err := h.svc.ListFolderContents(ctx, c, req.Msg.Parent)
	if err != nil {
		return nil, err
	}
	out := &catalogv1.ListFolderContentsResponse{
		FoldersHasMore: fc.FoldersHasMore,
		AssetsHasMore:  fc.AssetsHasMore,
		RolesHasMore:   fc.RolesHasMore,
		GroupsHasMore:  fc.GroupsHasMore,
	}
	for _, r := range fc.Folders {
		m := toFolderMsg(r.Folder)
		m.Path = r.Path
		m.Governed = r.Governed
		out.Folders = append(out.Folders, m)
	}
	for _, r := range fc.Assets {
		m := toAssetMsg(r.Asset)
		m.Path = r.Path
		out.Assets = append(out.Assets, m)
	}
	for _, r := range fc.Roles {
		out.Roles = append(out.Roles, toRoleMsg(r))
	}
	for _, r := range fc.Groups {
		out.Groups = append(out.Groups, toGroupMsg(r))
	}
	return connect.NewResponse(out), nil
}

// SearchCatalog returns visibility-filtered catalog hits matching the query.
func (h *Handler) SearchCatalog(ctx context.Context, req *connect.Request[catalogv1.SearchCatalogRequest]) (*connect.Response[catalogv1.SearchCatalogResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	hits, err := h.svc.SearchCatalog(ctx, c, req.Msg.Query, req.Msg.Limit)
	if err != nil {
		return nil, err
	}
	out := &catalogv1.SearchCatalogResponse{}
	for _, hit := range hits {
		out.Hits = append(out.Hits, &catalogv1.SearchHit{Kind: hit.Kind, Id: hit.ID, Name: hit.Name, Path: hit.Path})
	}
	return connect.NewResponse(out), nil
}
