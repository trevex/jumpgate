package access

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// SubjectView is the resolved display for a (user XOR group) subject.
type SubjectView struct {
	Kind        string // "user" | "group"
	DisplayName string
	FolderPath  string // group home; empty for users
	MemberCount int32  // 0 for users
	Active      bool   // user active; true for groups
}

// resolveSubject resolves display for exactly one of user/group. Missing rows degrade
// to an empty view rather than erroring, so a partial roster still renders.
func (s *Service) resolveSubject(ctx context.Context, user, group pgtype.UUID) SubjectView {
	if group.Valid {
		v := SubjectView{Kind: "group", Active: true}
		if g, err := s.q.GetGroup(ctx, uuid.UUID(group.Bytes)); err == nil {
			v.DisplayName = g.Name
			if g.FolderID.Valid {
				if fp, err := s.q.FolderPath(ctx, uuid.UUID(g.FolderID.Bytes)); err == nil {
					v.FolderPath = fp
				}
			}
		}
		if n, err := s.q.CountGroupMembers(ctx, uuid.UUID(group.Bytes)); err == nil {
			v.MemberCount = n
		}
		return v
	}
	v := SubjectView{Kind: "user"}
	if u, err := s.q.GetUserByID(ctx, uuid.UUID(user.Bytes)); err == nil {
		v.DisplayName = u.DisplayName
		v.Active = !u.DeactivatedAt.Valid
	}
	return v
}

// scopePath renders a role binding's scope as a dotted path, or "global".
func (s *Service) scopePath(ctx context.Context, scopeFolder, scopeAsset pgtype.UUID) string {
	if scopeAsset.Valid {
		if a, err := s.q.GetAsset(ctx, uuid.UUID(scopeAsset.Bytes)); err == nil {
			if fp, err := s.q.FolderPath(ctx, a.FolderID); err == nil && fp != "" {
				return a.Name + "." + fp
			}
			return a.Name
		}
		return ""
	}
	if scopeFolder.Valid {
		if fp, err := s.q.FolderPath(ctx, uuid.UUID(scopeFolder.Bytes)); err == nil {
			return fp
		}
		return ""
	}
	return "global"
}

// roleName resolves a role's name (best-effort, empty on miss).
func (s *Service) roleName(ctx context.Context, roleID uuid.UUID) string {
	if r, err := s.q.GetRole(ctx, roleID); err == nil {
		return r.Name
	}
	return ""
}
