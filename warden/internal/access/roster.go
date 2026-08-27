package access

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// RosterNodeView is one resolved roster entry (a user or group node).
type RosterNodeView struct {
	Subject     SubjectView
	SubjectID   string
	Source      string // "explicit" | "via_role"
	ViaRoleID   string
	ViaRoleName string
}

// PolicyRoster resolves the requester and approver rosters for a policy: explicit
// subjects of each kind, plus (when includeViaRole is set) standing holders of the
// policy's requester/approver role on the policy's scope object. Every subject is
// fully resolved for display in SQL — there is no per-row Go resolution here. Groups
// are returned as nodes (not expanded). Role-default policies (no scope object) and
// callers without binding-read (includeViaRole=false) resolve explicit subjects only.
func (s *Service) PolicyRoster(ctx context.Context, policyID uuid.UUID, includeViaRole bool) (requesters, approvers []RosterNodeView, err error) {
	p, err := s.q.GetRequestPolicy(ctx, policyID)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeNotFound, err)
	}
	objKind, objID, hasScope := policyScopeObject(p)

	build := func(kind string, roleID pgtype.UUID) ([]RosterNodeView, error) {
		nodes := map[string]*RosterNodeView{}
		order := []string{}
		add := func(v *RosterNodeView) {
			if _, ok := nodes[v.SubjectID]; !ok {
				nodes[v.SubjectID] = v
				order = append(order, v.SubjectID)
			}
		}
		subs, err := s.q.ListPolicyRosterSubjects(ctx, sqlc.ListPolicyRosterSubjectsParams{
			PolicyID: policyID,
			Kind:     kind,
		})
		if err != nil {
			return nil, err
		}
		for _, r := range subs {
			add(&RosterNodeView{
				Subject: SubjectView{
					Kind:        r.SubjectKind,
					DisplayName: r.DisplayName,
					FolderPath:  r.FolderPath,
					MemberCount: r.GroupMemberCount,
					Active:      r.Active.Bool,
				},
				SubjectID: pgUUIDStr(r.SubjectUserID, r.SubjectGroupID),
				Source:    "explicit",
			})
		}
		if includeViaRole && roleID.Valid && hasScope {
			holders, err := s.q.RoleStandingHolders(ctx, sqlc.RoleStandingHoldersParams{
				RoleID:     uuid.UUID(roleID.Bytes),
				ObjectKind: objKind,
				ObjectID:   objID,
			})
			if err != nil {
				return nil, err
			}
			for _, h := range holders {
				add(&RosterNodeView{
					Subject: SubjectView{
						Kind:        h.SubjectKind,
						DisplayName: h.DisplayName,
						FolderPath:  h.FolderPath,
						MemberCount: h.GroupMemberCount,
						Active:      h.Active.Bool,
					},
					SubjectID:   pgUUIDStr(h.SubjectUserID, h.SubjectGroupID),
					Source:      "via_role",
					ViaRoleID:   h.ViaRoleID.String(),
					ViaRoleName: h.ViaRoleName,
				})
			}
		}
		out := make([]RosterNodeView, 0, len(order))
		for _, id := range order {
			out = append(out, *nodes[id])
		}
		return out, nil
	}

	if requesters, err = build("requester", p.RequesterRoleID); err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, err)
	}
	if approvers, err = build("approver", p.ApproverRoleID); err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, err)
	}
	return requesters, approvers, nil
}

// policyScopeObject returns the (kind,id,ok) of the object a policy is scoped to.
func policyScopeObject(p sqlc.RequestPolicy) (string, uuid.UUID, bool) {
	if p.ScopeAssetID.Valid {
		return "asset", uuid.UUID(p.ScopeAssetID.Bytes), true
	}
	if p.ScopeFolderID.Valid {
		return "folder", uuid.UUID(p.ScopeFolderID.Bytes), true
	}
	return "", uuid.Nil, false
}

// pgUUIDStr returns the string of whichever of the two optional UUIDs is set.
func pgUUIDStr(user, group pgtype.UUID) string {
	if group.Valid {
		return uuid.UUID(group.Bytes).String()
	}
	return uuid.UUID(user.Bytes).String()
}
