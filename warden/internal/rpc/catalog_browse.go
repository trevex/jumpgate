package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// GetAssetDisplay returns an asset's decision context — path, kind, and for SSH the
// target address, host public key, and available logins (login + kind) — for an
// approver or requester to judge a pending access request, WITHOUT any secret
// references. Authorized by catalog:asset:read at the asset scope OR by being party
// to a pending access request that references the asset. Existence-hiding: a caller
// with neither, and a missing asset, both return NotFound (catalog topology rule).
func (s *CatalogServer) GetAssetDisplay(ctx context.Context, req *connect.Request[catalogv1.GetAssetDisplayRequest]) (*connect.Response[catalogv1.GetAssetDisplayResponse], error) {
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	// Authorize: catalog:asset:read, else party to a pending request for this asset.
	if capErr := s.requireCap(ctx, "catalog:asset:read", authz.AssetScope(id)); capErr != nil {
		u, ok := auth.UserFromContext(ctx)
		if !ok || s.reqReads == nil {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		allowed, err := s.reqReads.CanReadForRequest(ctx, u.ID, accessrequest.ReqEntityAsset, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !allowed {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
	}
	a, err := s.q.GetAsset(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	disp := &catalogv1.AssetDisplay{
		Id:       a.ID.String(),
		FolderId: a.FolderID.String(),
		Name:     a.Name,
		Kind:     a.Kind,
	}
	// Reuse the same folder-path lookup GetAsset uses so the dotted path matches.
	if fp, ferr := s.q.FolderPath(ctx, a.FolderID); ferr == nil {
		disp.FolderPath = fp
		disp.Path = joinPath(fp, a.Name)
	}
	// SSH connection config is optional; a config-less asset returns no ssh oneof.
	cfg, err := s.q.GetSSHAssetConfig(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&catalogv1.GetAssetDisplayResponse{Asset: disp}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	logins, err := s.q.ListSSHAssetLogins(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	ssh := &catalogv1.SSHConfigDisplay{
		HostPublicKey: cfg.HostPublicKey,
		TargetAddress: cfg.TargetAddress,
	}
	for _, l := range logins {
		// Copy ONLY login + kind — never l.SecretID; SSHLoginDisplay has no such field.
		ssh.Logins = append(ssh.Logins, &catalogv1.SSHLoginDisplay{Login: l.Login, Kind: l.Kind})
	}
	disp.Config = &catalogv1.AssetDisplay_Ssh{Ssh: ssh}
	return connect.NewResponse(&catalogv1.GetAssetDisplayResponse{Asset: disp}), nil
}

// GetAssetAccess returns the caller's roles on one asset; NotFound if invisible.
func (s *CatalogServer) GetAssetAccess(ctx context.Context, req *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
	}
	roles, err := s.authorizer.RolesOnAsset(ctx, u.ID, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// The management read cap bypasses the data-plane visibility gate (admins
	// hold ** so this stays a no-op for them). Callers without it and without any
	// role on the asset are still visible via the CONNECT arm — a folder/global
	// ssh:login cascade entitling ≥1 of the asset's own logins (authz.AssetVisible).
	// Only a caller matching none of these gets the existence-hiding NotFound.
	mgmtOK := s.requireCap(ctx, "catalog:asset:read", authz.AssetScope(id)) == nil
	if !mgmtOK && len(roles.Active) == 0 && len(roles.Requestable) == 0 {
		visible, err := authz.AssetVisible(ctx, s.authorizer, u.ID, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !visible {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
	}
	resp := &catalogv1.GetAssetAccessResponse{}
	for _, r := range roles.Active {
		resp.ActiveRoleIds = append(resp.ActiveRoleIds, r.String())
	}
	for _, r := range roles.Requestable {
		resp.RequestableRoleIds = append(resp.RequestableRoleIds, r.String())
	}
	if resp.ActiveRoles, err = roleRefs(ctx, s.q, roles.Active); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if resp.RequestableRoles, err = roleRefs(ctx, s.q, roles.Requestable); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	caps, err := authz.ConnectCapabilities(ctx, s.authorizer, u.ID, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp.Capabilities = []string(caps)
	// Management capabilities drive the authoring affordances (rename/move/delete/
	// edit config). These are the full scope-cascade caps WITHOUT the `**` strip —
	// mirroring GetFolderAccess — so an admin holding `**` can author the asset even
	// though `**` confers no connect ability (and so is absent from Capabilities).
	mgmtCaps, err := s.authorizer.CapabilitiesOnScope(ctx, u.ID, authz.AssetScope(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp.ManagementCapabilities = []string(mgmtCaps)
	return connect.NewResponse(resp), nil
}

// contentsSlice is the bounded first-slice size returned by ListFolderContents.
const contentsSlice = 50

// ListFolderContents returns the first bounded slice (contentsSlice items per
// kind) of folders, assets, roles, and groups visible to the caller directly
// under the named parent folder (default root). has_more flags indicate whether
// additional items exist beyond the returned slice; callers wanting full
// pagination should use the dedicated per-kind List RPCs.
//
// The parent is existence-gated via resolveParentFolder (same as ListAssets /
// ListFolders), so an unknown or invisible parent returns NotFound. Cascade is
// intentionally false: only direct children are aggregated here.
func (s *CatalogServer) ListFolderContents(ctx context.Context, req *connect.Request[catalogv1.ListFolderContentsRequest]) (*connect.Response[catalogv1.ListFolderContentsResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	parent, err := s.resolveParentFolder(ctx, u.ID, req.Msg.Parent)
	if err != nil {
		return nil, err
	}

	out := &catalogv1.ListFolderContentsResponse{}

	// ── folders ───────────────────────────────────────────────────────────────
	visibleFolders, err := s.authorizer.VisibleFoldersUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
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
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.FoldersHasMore = true
			rows = rows[:contentsSlice]
		}
		allPaths, err := s.q.FolderPaths(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		pathByID := make(map[string]string, len(allPaths))
		for _, p := range allPaths {
			pathByID[p.ID.String()] = p.Path
		}
		for i := range rows {
			m := toFolderMsg(rows[i])
			m.Path = pathByID[rows[i].ID.String()]
			m.Governed = folderGovByID[rows[i].ID]
			out.Folders = append(out.Folders, m)
		}
	}

	// ── assets ────────────────────────────────────────────────────────────────
	assetIDs, err := s.authorizer.VisibleAssetsUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(assetIDs) > 0 {
		rows, err := s.q.ListAssetsByIDsPaged(ctx, sqlc.ListAssetsByIDsPagedParams{
			Ids: assetIDs,
			Lim: contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.AssetsHasMore = true
			rows = rows[:contentsSlice]
		}
		pathByFolder := map[uuid.UUID]string{}
		for i := range rows {
			m := toAssetMsg(rows[i])
			fp, ok := pathByFolder[rows[i].FolderID]
			if !ok {
				if fp, err = s.q.FolderPath(ctx, rows[i].FolderID); err != nil {
					return nil, connect.NewError(connect.CodeInternal, err)
				}
				pathByFolder[rows[i].FolderID] = fp
			}
			m.Path = joinPath(fp, rows[i].Name)
			out.Assets = append(out.Assets, m)
		}
	}

	// ── roles ─────────────────────────────────────────────────────────────────
	roleIDs, err := s.authorizer.VisibleRolesUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(roleIDs) > 0 {
		rows, err := s.q.ListRolesByIDsPaged(ctx, sqlc.ListRolesByIDsPagedParams{
			Column1: roleIDs,
			Lim:     contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.RolesHasMore = true
			rows = rows[:contentsSlice]
		}
		pathByFolder := map[uuid.UUID]string{}
		for i := range rows {
			caps, err := roleCapsStrings(ctx, s.q, rows[i].ID)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			m := toAccessRoleMsg(rows[i], caps)
			if rows[i].FolderID.Valid {
				fid := uuidFromPg(rows[i].FolderID)
				p, ok := pathByFolder[fid]
				if !ok {
					if p, err = s.q.FolderPath(ctx, fid); err != nil {
						return nil, connect.NewError(connect.CodeInternal, err)
					}
					pathByFolder[fid] = p
				}
				m.FolderPath = p
			}
			out.Roles = append(out.Roles, m)
		}
	}

	// ── groups ────────────────────────────────────────────────────────────────
	groupIDs, err := s.authorizer.VisibleGroupsUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(groupIDs) > 0 {
		rows, err := s.q.ListGroupsByIDsPaged(ctx, sqlc.ListGroupsByIDsPagedParams{
			Column1: groupIDs,
			Lim:     contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.GroupsHasMore = true
			rows = rows[:contentsSlice]
		}
		pathByFolder := map[uuid.UUID]string{}
		for i := range rows {
			m := toGroupMsg(rows[i])
			if rows[i].FolderID.Valid {
				fid := uuidFromPg(rows[i].FolderID)
				p, ok := pathByFolder[fid]
				if !ok {
					if p, err = s.q.FolderPath(ctx, fid); err != nil {
						return nil, connect.NewError(connect.CodeInternal, err)
					}
					pathByFolder[fid] = p
				}
				m.FolderPath = p
			}
			out.Groups = append(out.Groups, m)
		}
	}

	return connect.NewResponse(out), nil
}

// searchDefaultLimit / searchMaxLimit bound the number of hits SearchCatalog
// returns when the request omits or over-specifies a limit.
const (
	searchDefaultLimit = 20
	searchMaxLimit     = 50
)

// SearchCatalog finds catalog entities (folders, assets, roles, groups) whose name
// contains the query (case-insensitive substring), restricted to what the caller may
// see. Visibility is enforced by reusing the same Visible*Under predicates that back
// the browse RPCs (with parent=root, cascade=true → every id of that kind the caller
// may see across the whole tree), so an entity the caller cannot see is never
// returned — existence is hidden by construction. Any authenticated caller.
//
// Hits are filled kind by kind in the order folders → assets → roles → groups, each
// kind's entities loaded name-ordered, and the whole result is capped at the clamped
// limit (a best-effort search; truncation is acceptable). An empty query returns no
// hits rather than dumping the whole visible catalog.
// likeEscaper escapes the LIKE metacharacters so a user query matches as a literal
// substring (preserving the previous strings.Contains semantics); backslash is the
// default ILIKE escape character.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// likePattern wraps q as a case-insensitive substring ILIKE pattern.
func likePattern(q string) string { return "%" + likeEscaper.Replace(q) + "%" }

// SearchCatalog returns visibility-filtered catalog hits (folders, assets, roles,
// groups) whose name matches the query substring, up to the requested limit. Name
// matching runs in SQL via the pg_trgm-indexed ILIKE within each kind's visible set.
func (s *CatalogServer) SearchCatalog(ctx context.Context, req *connect.Request[catalogv1.SearchCatalogRequest]) (*connect.Response[catalogv1.SearchCatalogResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	limit := req.Msg.Limit
	if limit <= 0 {
		limit = searchDefaultLimit
	}
	if limit > searchMaxLimit {
		limit = searchMaxLimit
	}

	q := strings.ToLower(strings.TrimSpace(req.Msg.Query))
	out := &catalogv1.SearchCatalogResponse{}
	if q == "" {
		return connect.NewResponse(out), nil
	}

	// Name matching happens in SQL via a pg_trgm-indexed ILIKE (see likePattern),
	// so search fetches only the name-matching rows within the visible set rather
	// than materializing the whole visible catalog and substring-filtering in Go.
	pattern := likePattern(q)
	full := func() bool { return len(out.Hits) >= int(limit) }
	// len(out.Hits) is bounded by limit (<= searchMaxLimit), so the conversion cannot overflow.
	remaining := func() int32 { return limit - int32(len(out.Hits)) } //nolint:gosec // bounded by searchMaxLimit

	// Home-folder path lookup, memoized across kinds (roles/groups reuse it).
	pathByFolder := map[uuid.UUID]string{}
	folderPath := func(fid uuid.UUID) (string, error) {
		if p, ok := pathByFolder[fid]; ok {
			return p, nil
		}
		p, err := s.q.FolderPath(ctx, fid)
		if err != nil {
			return "", err
		}
		pathByFolder[fid] = p
		return p, nil
	}

	// ── folders ────────────────────────────────────────────────────────────────
	visibleFolders, err := s.authorizer.VisibleFoldersUnder(ctx, u.ID, uuid.Nil, true)
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
			fp, err := folderPath(rows[i].ID)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			out.Hits = append(out.Hits, &catalogv1.SearchHit{
				Kind: "folder", Id: rows[i].ID.String(), Name: rows[i].Name, Path: fp,
			})
		}
	}

	// ── assets ─────────────────────────────────────────────────────────────────
	assetIDs, err := s.authorizer.VisibleAssetsUnder(ctx, u.ID, uuid.Nil, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(assetIDs) > 0 && !full() {
		rows, err := s.q.SearchAssetsByIDs(ctx, sqlc.SearchAssetsByIDsParams{Column1: assetIDs, Name: pattern, Limit: remaining()})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		for i := range rows {
			fp, err := folderPath(rows[i].FolderID)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			out.Hits = append(out.Hits, &catalogv1.SearchHit{
				Kind: "asset", Id: rows[i].ID.String(), Name: rows[i].Name, Path: joinPath(fp, rows[i].Name),
			})
		}
	}

	// ── roles ──────────────────────────────────────────────────────────────────
	roleIDs, err := s.authorizer.VisibleRolesUnder(ctx, u.ID, uuid.Nil, true)
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
			// just its name.
			path := rows[i].Name
			if rows[i].FolderID.Valid {
				fp, err := folderPath(uuidFromPg(rows[i].FolderID))
				if err != nil {
					return nil, connect.NewError(connect.CodeInternal, err)
				}
				path = joinPath(fp, rows[i].Name)
			}
			out.Hits = append(out.Hits, &catalogv1.SearchHit{
				Kind: "role", Id: rows[i].ID.String(), Name: rows[i].Name, Path: path,
			})
		}
	}

	// ── groups ─────────────────────────────────────────────────────────────────
	groupIDs, err := s.authorizer.VisibleGroupsUnder(ctx, u.ID, uuid.Nil, true)
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
			// is just its name.
			path := rows[i].Name
			if rows[i].FolderID.Valid {
				fp, err := folderPath(uuidFromPg(rows[i].FolderID))
				if err != nil {
					return nil, connect.NewError(connect.CodeInternal, err)
				}
				path = rows[i].Name + "@" + fp
			}
			out.Hits = append(out.Hits, &catalogv1.SearchHit{
				Kind: "group", Id: rows[i].ID.String(), Name: rows[i].Name, Path: path,
			})
		}
	}

	return connect.NewResponse(out), nil
}

// GetFolderAccess returns the caller's management capabilities on one folder;
// NotFound (existence hiding) if the caller has no relationship to it — neither
// a capability on its scope nor a visible asset in its subtree.
func (s *CatalogServer) GetFolderAccess(ctx context.Context, req *connect.Request[catalogv1.GetFolderAccessRequest]) (*connect.Response[catalogv1.GetFolderAccessResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	id, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	caps, err := s.authorizer.CapabilitiesOnScope(ctx, u.ID, authz.FolderScope(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(caps) == 0 {
		// No direct caps here: the folder is disclosable only if it is path-visible
		// (a breadcrumb on the way to something the user can see/administer, e.g. a
		// delegate viewing the ancestors above the subtree they govern). This
		// subsumes the old "has a visible asset in its subtree" check.
		vis, err := s.authorizer.FolderPathVisible(ctx, u.ID, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !vis {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
	}
	return connect.NewResponse(&catalogv1.GetFolderAccessResponse{Capabilities: []string(caps)}), nil
}
