package accessrequest

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// PageParams carries decoded keyset cursor fields for time-ordered lists.
// AfterTs and AfterID are zero/nil when on the first page.
type PageParams struct {
	AfterTs *time.Time
	AfterID uuid.UUID
	Limit   int64
}

// PageCursor is a keyset position that can be encoded into a next-page token.
// It carries the (created_at, id) of the LAST SQL ROW SCANNED, which may
// differ from the last row returned when Go-side filtering drops rows.
type PageCursor struct {
	Ts time.Time
	ID uuid.UUID
}

// intervalToDuration converts a pgtype.Interval to a time.Duration, folding
// Months/Days with civil-day approximations (30d month, 24h day) so admin caps
// expressed in those units are honored. Invalid/zero → (0, false).
func intervalToDuration(iv pgtype.Interval) (time.Duration, bool) {
	if !iv.Valid {
		return 0, false
	}
	const day = 24 * time.Hour
	d := time.Duration(iv.Months)*30*day + time.Duration(iv.Days)*day + time.Duration(iv.Microseconds)*time.Microsecond
	if d <= 0 {
		return 0, false
	}
	return d, true
}

// clamp returns min(dur, ruleMax if set else maxTTL, maxTTL).
func (s *Service) clamp(dur time.Duration, ruleMax pgtype.Interval) time.Duration {
	granted := dur
	if ceiling, ok := intervalToDuration(ruleMax); ok {
		if granted > ceiling {
			granted = ceiling
		}
	}
	if granted > s.maxTTL {
		granted = s.maxTTL
	}
	return granted
}

// durationToInterval encodes a positive duration as a Microseconds interval.
func durationToInterval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: int64(d / time.Microsecond), Valid: true}
}

// mustDuration converts a stored granted_duration interval to a Duration; if the
// interval is somehow invalid it falls back to a safe non-zero minimum so a
// granted request always yields a live grant window.
func mustDuration(iv pgtype.Interval) time.Duration {
	if d, ok := intervalToDuration(iv); ok {
		return d
	}
	return time.Minute
}

// toRequest maps a sqlc.AccessRequest plus derived fields to the DTO.
func toRequest(r sqlc.AccessRequest, approvals int, grantID uuid.UUID) Request {
	out := Request{
		ID:                r.ID,
		RequesterID:       r.RequesterUserID,
		RoleID:            r.RoleID,
		AssetID:           r.AssetID,
		Status:            r.Status,
		RequiredApprovals: int(r.RequiredApprovals),
		ApprovalsSoFar:    approvals,
		Reason:            r.Reason,
		CreatedAt:         r.CreatedAt,
		GrantID:           grantID,
	}
	if r.ResolvedAt.Valid {
		out.ResolvedAt = r.ResolvedAt.Time
	}
	return out
}

// GrantDTO maps a raw sqlc.AccessGrant to the transport DTO (used by handlers
// that receive the revoked grant from RevokeGrant).
func (s *Service) GrantDTO(g sqlc.AccessGrant) Grant { return toGrant(g) }

// toGrant maps a sqlc.AccessGrant to the DTO, deriving the active flag.
func toGrant(g sqlc.AccessGrant) Grant {
	out := Grant{
		ID:            g.ID,
		RoleID:        g.RoleID,
		AssetID:       g.ScopeAssetID,
		SubjectUserID: g.SubjectUserID,
		GrantedAt:     g.GrantedAt,
		ExpiresAt:     g.ExpiresAt,
		Active:        !g.RevokedAt.Valid && g.ExpiresAt.After(time.Now()),
	}
	if g.RevokedAt.Valid {
		out.RevokedAt = g.RevokedAt.Time
	}
	if g.RevokedReason.Valid {
		out.RevokedReason = g.RevokedReason.String
	}
	return out
}

func toGrants(rows []sqlc.AccessGrant) []Grant {
	out := make([]Grant, 0, len(rows))
	for _, g := range rows {
		out = append(out, toGrant(g))
	}
	return out
}
