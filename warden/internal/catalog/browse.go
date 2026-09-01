package catalog

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// AssetDisplayResult is an asset's decision context: the asset row, its folder and
// dotted paths, and optional typed config (no secret material). At most one config
// pair is set, per the asset's kind.
type AssetDisplayResult struct {
	Asset      sqlc.Asset
	FolderPath string
	Path       string
	Config     *sqlc.SshAssetConfig      // kind == "ssh"
	Logins     []sqlc.SshAssetLogin      // kind == "ssh"
	PGConfig   *sqlc.PostgresAssetConfig // kind == "postgres"
	PGLogins   []sqlc.PostgresAssetLogin // kind == "postgres"
	RDPConfig  *sqlc.RdpAssetConfig      // kind == "rdp"
	RDPLogins  []sqlc.RdpAssetLogin      // kind == "rdp"
}

// FolderContents is the bounded per-kind first slice returned by ListFolderContents.
type FolderContents struct {
	Folders        []FolderRow
	FoldersHasMore bool
	Assets         []AssetRow
	AssetsHasMore  bool
	Roles          []RoleRow
	RolesHasMore   bool
	Groups         []GroupRow
	GroupsHasMore  bool
}

// roleRefs resolves role ids to {id, name, folder_path}, computing each distinct
// scoped folder's path once. Preserves the input order.
func (s *Service) roleRefs(ctx context.Context, ids []uuid.UUID) ([]RoleRef, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.q.ListRolesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	refByID := make(map[uuid.UUID]RoleRef, len(rows))
	for _, r := range rows {
		// folder_path() yields "" for a global/folder-less role, matching the prior
		// "leave FolderPath unset when folder_id is invalid" behavior.
		refByID[r.Role.ID] = RoleRef{ID: r.Role.ID.String(), Name: r.Role.Name, FolderPath: r.FolderPath}
	}
	out := make([]RoleRef, 0, len(ids))
	for _, id := range ids {
		if ref, ok := refByID[id]; ok {
			out = append(out, ref)
		}
	}
	return out, nil
}

// GetAssetDisplay returns an asset's decision context — path, kind, and for SSH the
// target address, host public key, and available logins (login + kind) — WITHOUT any
// secret references. Authorized by catalog:asset:read at the asset scope OR by being
// party to a pending access request that references the asset. Existence-hiding: a
// caller with neither, and a missing asset, both return NotFound.
func (s *Service) GetAssetDisplay(ctx context.Context, caller uuid.UUID, id uuid.UUID) (AssetDisplayResult, error) {
	// Authorize: catalog:asset:read (or subtree-wide catalog:folder:read), else party
	// to a pending request for this asset.
	if capErr := s.guard.RequireReadCap(ctx, caller, authz.AssetReadCap, authz.AssetScope(id)); capErr != nil {
		if s.reqReads == nil {
			return AssetDisplayResult{}, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		allowed, err := s.reqReads.CanReadForRequest(ctx, caller, accessrequest.ReqEntityAsset, id)
		if err != nil {
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		if !allowed {
			return AssetDisplayResult{}, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
	}
	a, err := s.q.GetAsset(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AssetDisplayResult{}, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
	}
	res := AssetDisplayResult{Asset: a}
	// Reuse the same folder-path lookup GetAsset uses so the dotted path matches.
	if fp, ferr := s.q.FolderPath(ctx, a.FolderID); ferr == nil {
		res.FolderPath = fp
		res.Path = joinPath(fp, a.Name)
	}
	// Connection config is optional; a config-less asset returns no config oneof.
	switch a.Kind {
	case "ssh":
		cfg, err := s.q.GetSSHAssetConfig(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return res, nil
			}
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		logins, err := s.q.ListSSHAssetLogins(ctx, id)
		if err != nil {
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		res.Config, res.Logins = &cfg, logins
	case "postgres":
		cfg, err := s.q.GetPostgresAssetConfig(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return res, nil
			}
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		logins, err := s.q.ListPostgresAssetLogins(ctx, id)
		if err != nil {
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		res.PGConfig, res.PGLogins = &cfg, logins
	case "rdp":
		cfg, err := s.q.GetRDPAssetConfig(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return res, nil
			}
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		logins, err := s.q.ListRDPAssetLogins(ctx, id)
		if err != nil {
			return AssetDisplayResult{}, connect.NewError(connect.CodeInternal, err)
		}
		res.RDPConfig, res.RDPLogins = &cfg, logins
	}
	return res, nil
}

// GetAssetAccess returns the caller's roles on one asset; NotFound if invisible.
func (s *Service) GetAssetAccess(ctx context.Context, caller uuid.UUID, id uuid.UUID) (AssetAccess, error) {
	roles, err := s.authz.RolesOnAsset(ctx, caller, id)
	if err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	// The management read cap bypasses the data-plane visibility gate (admins hold **
	// so this stays a no-op for them). Callers without it and without any role on the
	// asset are still visible via the CONNECT arm — a folder/global ssh:login cascade
	// entitling ≥1 of the asset's own logins (authz.AssetVisible). Only a caller
	// matching none of these gets the existence-hiding NotFound.
	mgmtOK := s.guard.RequireReadCap(ctx, caller, authz.AssetReadCap, authz.AssetScope(id)) == nil
	if !mgmtOK && len(roles.Active) == 0 && len(roles.Requestable) == 0 {
		visible, err := authz.AssetVisible(ctx, s.authz, caller, id)
		if err != nil {
			return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
		}
		if !visible {
			return AssetAccess{}, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
	}
	out := AssetAccess{}
	for _, r := range roles.Active {
		out.ActiveRoleIDs = append(out.ActiveRoleIDs, r.String())
	}
	for _, r := range roles.Requestable {
		out.RequestableRoleIDs = append(out.RequestableRoleIDs, r.String())
	}
	if out.ActiveRoles, err = s.roleRefs(ctx, roles.Active); err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	if out.RequestableRoles, err = s.roleRefs(ctx, roles.Requestable); err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	caps, err := authz.ConnectCapabilities(ctx, s.authz, caller, id)
	if err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	out.Capabilities = []string(caps)
	// EntitledLogins is the connect predicate resolved against reality: the caller's
	// connect capabilities intersected with the asset's own configured SSH logins.
	// This is what the UI must show as "usable logins" — a login the caps cover but
	// the asset does not declare is not usable and must not appear. ListSSHAssetLogins
	// returns no rows for a non-SSH (config-less) asset, so entitled logins is empty.
	loginRows, err := s.q.ListSSHAssetLogins(ctx, id)
	if err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	loginNames := make([]string, 0, len(loginRows))
	for _, l := range loginRows {
		loginNames = append(loginNames, l.Login)
	}
	entitled, err := authz.EntitledLogins(ctx, s.authz, caller, id, loginNames)
	if err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	out.EntitledLogins = entitled
	// Management capabilities drive the authoring affordances (rename/move/delete/
	// edit config). These are the full scope-cascade caps WITHOUT the `**` strip —
	// mirroring GetFolderAccess — so an admin holding `**` can author the asset even
	// though `**` confers no connect ability (and so is absent from Capabilities).
	mgmtCaps, err := s.authz.CapabilitiesOnScope(ctx, caller, authz.AssetScope(id))
	if err != nil {
		return AssetAccess{}, connect.NewError(connect.CodeInternal, err)
	}
	out.ManagementCapabilities = []string(mgmtCaps)
	return out, nil
}

// contentsSlice is the bounded first-slice size returned by ListFolderContents.
const contentsSlice = 50

// ListFolderContents returns the first bounded slice (contentsSlice items per kind)
// of folders, assets, roles, and groups visible to the caller directly under the
// named parent folder (default root). has_more flags indicate whether additional
// items exist beyond the returned slice. The parent is existence-gated via
// resolveParentFolder; cascade is intentionally false (only direct children).
func (s *Service) ListFolderContents(ctx context.Context, caller uuid.UUID, parentRef string) (FolderContents, error) {
	parent, err := s.resolveParentFolder(ctx, caller, parentRef)
	if err != nil {
		return FolderContents{}, err
	}

	out := FolderContents{}

	// ── folders ───────────────────────────────────────────────────────────────
	visibleFolders, err := s.authz.VisibleFoldersUnder(ctx, caller, parent, false)
	if err != nil {
		return FolderContents{}, connect.NewError(connect.CodeInternal, err)
	}
	folderGovByID := make(map[uuid.UUID]bool, len(visibleFolders))
	for _, vf := range visibleFolders {
		folderGovByID[vf.ID] = vf.Governed
	}
	folderIDs := authz.FolderIDsOf(visibleFolders)
	if len(folderIDs) > 0 {
		rows, err := s.q.ListFoldersByIDsPaged(ctx, sqlc.ListFoldersByIDsPagedParams{
			Ids: folderIDs,
			Lim: contentsSlice + 1,
		})
		if err != nil {
			return FolderContents{}, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.FoldersHasMore = true
			rows = rows[:contentsSlice]
		}
		for i := range rows {
			out.Folders = append(out.Folders, FolderRow{Folder: rows[i].Folder, Path: rows[i].FolderPath, Governed: folderGovByID[rows[i].Folder.ID]})
		}
	}

	// ── assets ────────────────────────────────────────────────────────────────
	assetIDs, err := s.authz.VisibleAssetsUnder(ctx, caller, parent, false)
	if err != nil {
		return FolderContents{}, connect.NewError(connect.CodeInternal, err)
	}
	if len(assetIDs) > 0 {
		rows, err := s.q.ListAssetsByIDsPaged(ctx, sqlc.ListAssetsByIDsPagedParams{
			Ids: assetIDs,
			Lim: contentsSlice + 1,
		})
		if err != nil {
			return FolderContents{}, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.AssetsHasMore = true
			rows = rows[:contentsSlice]
		}
		for i := range rows {
			out.Assets = append(out.Assets, AssetRow{Asset: rows[i].Asset, Path: joinPath(rows[i].FolderPath, rows[i].Asset.Name)})
		}
	}

	// ── roles ─────────────────────────────────────────────────────────────────
	roleIDs, err := s.authz.VisibleRolesUnder(ctx, caller, parent, false)
	if err != nil {
		return FolderContents{}, connect.NewError(connect.CodeInternal, err)
	}
	if len(roleIDs) > 0 {
		rows, err := s.q.ListRolesByIDsPaged(ctx, sqlc.ListRolesByIDsPagedParams{
			Column1: roleIDs,
			Lim:     contentsSlice + 1,
		})
		if err != nil {
			return FolderContents{}, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.RolesHasMore = true
			rows = rows[:contentsSlice]
		}
		pageIDs := make([]uuid.UUID, len(rows))
		for i := range rows {
			pageIDs[i] = rows[i].Role.ID
		}
		capsByID, err := apiguard.RoleCapsByRoleIDs(ctx, s.q, pageIDs)
		if err != nil {
			return FolderContents{}, connect.NewError(connect.CodeInternal, err)
		}
		for i := range rows {
			out.Roles = append(out.Roles, RoleRow{Role: rows[i].Role, Caps: capsByID[rows[i].Role.ID], FolderPath: rows[i].FolderPath})
		}
	}

	// ── groups ────────────────────────────────────────────────────────────────
	groupIDs, err := s.authz.VisibleGroupsUnder(ctx, caller, parent, false)
	if err != nil {
		return FolderContents{}, connect.NewError(connect.CodeInternal, err)
	}
	if len(groupIDs) > 0 {
		rows, err := s.q.ListGroupsByIDsPaged(ctx, sqlc.ListGroupsByIDsPagedParams{
			Column1: groupIDs,
			Lim:     contentsSlice + 1,
		})
		if err != nil {
			return FolderContents{}, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.GroupsHasMore = true
			rows = rows[:contentsSlice]
		}
		for i := range rows {
			out.Groups = append(out.Groups, GroupRow{Group: rows[i].Group, FolderPath: rows[i].FolderPath})
		}
	}

	return out, nil
}

// searchDefaultLimit / searchMaxLimit bound the number of hits SearchCatalog returns
// when the request omits or over-specifies a limit.
const (
	searchDefaultLimit = 20
	searchMaxLimit     = 50
)

// likeEscaper escapes the LIKE metacharacters so a user query matches as a literal
// substring; backslash is the default ILIKE escape character.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// likePattern wraps q as a case-insensitive substring ILIKE pattern.
func likePattern(q string) string { return "%" + likeEscaper.Replace(q) + "%" }

// SearchCatalog returns visibility-filtered catalog hits (folders, assets, roles,
// groups) whose name matches the query substring, up to the requested limit. Name
// matching runs in SQL via the pg_trgm-indexed ILIKE within each kind's visible set.
// An empty query returns no hits.
func (s *Service) SearchCatalog(ctx context.Context, caller uuid.UUID, query string, limit int32) ([]SearchHit, error) {
	if limit <= 0 {
		limit = searchDefaultLimit
	}
	if limit > searchMaxLimit {
		limit = searchMaxLimit
	}

	q := strings.ToLower(strings.TrimSpace(query))
	var hits []SearchHit
	if q == "" {
		return hits, nil
	}

	// Name matching happens in SQL via a pg_trgm-indexed ILIKE (see likePattern), so
	// search fetches only the name-matching rows within the visible set rather than
	// materializing the whole visible catalog and substring-filtering in Go.
	pattern := likePattern(q)
	full := func() bool { return len(hits) >= int(limit) }
	remaining := func() int64 { return int64(limit) - int64(len(hits)) }

	// ── folders ────────────────────────────────────────────────────────────────
	visibleFolders, err := s.authz.VisibleFoldersUnder(ctx, caller, uuid.Nil, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	folderIDs := authz.FolderIDsOf(visibleFolders)
	if len(folderIDs) > 0 && !full() {
		rows, err := s.q.SearchFoldersByIDs(ctx, sqlc.SearchFoldersByIDsParams{Column1: folderIDs, Name: pattern, Limit: remaining()})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		for i := range rows {
			hits = append(hits, SearchHit{Kind: "folder", ID: rows[i].Folder.ID.String(), Name: rows[i].Folder.Name, Path: rows[i].FolderPath})
		}
	}

	// ── assets ─────────────────────────────────────────────────────────────────
	assetIDs, err := s.authz.VisibleAssetsUnder(ctx, caller, uuid.Nil, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(assetIDs) > 0 && !full() {
		rows, err := s.q.SearchAssetsByIDs(ctx, sqlc.SearchAssetsByIDsParams{Column1: assetIDs, Name: pattern, Limit: remaining()})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		for i := range rows {
			hits = append(hits, SearchHit{Kind: "asset", ID: rows[i].Asset.ID.String(), Name: rows[i].Asset.Name, Path: joinPath(rows[i].FolderPath, rows[i].Asset.Name)})
		}
	}

	// ── roles ──────────────────────────────────────────────────────────────────
	roleIDs, err := s.authz.VisibleRolesUnder(ctx, caller, uuid.Nil, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(roleIDs) > 0 && !full() {
		rows, err := s.q.SearchRolesByIDs(ctx, sqlc.SearchRolesByIDsParams{Column1: roleIDs, Name: pattern, Limit: remaining()})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		for i := range rows {
			// A folder-scoped role is addressed "<role>.<folder-path>"; a global role is
			// just its name. folder_path() yields "" for a global role, and joinPath("",
			// name) == name, so this uniformly reproduces both cases.
			hits = append(hits, SearchHit{Kind: "role", ID: rows[i].Role.ID.String(), Name: rows[i].Role.Name, Path: joinPath(rows[i].FolderPath, rows[i].Role.Name)})
		}
	}

	// ── groups ─────────────────────────────────────────────────────────────────
	groupIDs, err := s.authz.VisibleGroupsUnder(ctx, caller, uuid.Nil, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(groupIDs) > 0 && !full() {
		rows, err := s.q.SearchGroupsByIDs(ctx, sqlc.SearchGroupsByIDsParams{Column1: groupIDs, Name: pattern, Limit: remaining()})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		for i := range rows {
			// A folder-homed group is addressed "<group>@<folder-path>"; a global group
			// is just its name. folder_path() yields "" for a global group (⟺ folder_id
			// NULL), so a non-empty path is exactly the folder-homed case.
			path := rows[i].Group.Name
			if rows[i].FolderPath != "" {
				path = rows[i].Group.Name + "@" + rows[i].FolderPath
			}
			hits = append(hits, SearchHit{Kind: "group", ID: rows[i].Group.ID.String(), Name: rows[i].Group.Name, Path: path})
		}
	}

	return hits, nil
}

// GetFolderAccess returns the caller's management capabilities on one folder;
// NotFound (existence hiding) if the caller has no relationship to it — neither a
// capability on its scope nor a path-visible relationship.
func (s *Service) GetFolderAccess(ctx context.Context, caller uuid.UUID, id uuid.UUID) ([]string, error) {
	caps, err := s.authz.CapabilitiesOnScope(ctx, caller, authz.FolderScope(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(caps) == 0 {
		// No direct caps here: the folder is disclosable only if it is path-visible
		// (a breadcrumb on the way to something the user can see/administer).
		vis, err := s.authz.FolderPathVisible(ctx, caller, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !vis {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
	}
	return []string(caps), nil
}
