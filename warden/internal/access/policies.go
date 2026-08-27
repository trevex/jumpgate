package access

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// CreateRequestPolicyInput is the proto-free request for CreateRequestPolicy (the
// caller and the derived policy scope are passed separately). Name is expected
// already normalized (lower-cased) by the handler.
type CreateRequestPolicyInput struct {
	RoleID             uuid.UUID
	ScopeFolder        pgtype.UUID
	ScopeAsset         pgtype.UUID
	RequiredApprovals  int32
	ApproverRole       pgtype.UUID
	RequesterRole      pgtype.UUID
	MaxDurationSeconds int64
	Name               string
}

// CreateRequestPolicy creates a JIT request policy for a role. The caller's
// access:policy:create capability at policyScope is gated by the handler; the service
// then enforces the no-escalation subset rule (requireGrantable) and the
// folder-scoped role containment invariant before writing the policy.
func (s *Service) CreateRequestPolicy(ctx context.Context, caller uuid.UUID, in CreateRequestPolicyInput, policyScope authz.Scope) (sqlc.RequestPolicy, error) {
	caps, err := s.guard.RoleCaps(ctx, in.RoleID)
	if err != nil {
		return sqlc.RequestPolicy{}, err
	}
	if err := s.guard.RequireGrantable(ctx, caller, caps, policyScope); err != nil {
		return sqlc.RequestPolicy{}, err
	}
	if err := s.containedInRoleSubtree(ctx, in.RoleID, in.ScopeFolder, in.ScopeAsset); err != nil {
		return sqlc.RequestPolicy{}, err
	}
	policy, err := s.q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            in.RoleID,
		ScopeFolderID:     in.ScopeFolder,
		ScopeAssetID:      in.ScopeAsset,
		RequiredApprovals: in.RequiredApprovals,
		ApproverRoleID:    in.ApproverRole,
		RequesterRoleID:   in.RequesterRole,
		MaxDuration:       secondsToInterval(in.MaxDurationSeconds),
		Name:              pgconv.Text(in.Name),
	})
	if err != nil {
		return sqlc.RequestPolicy{}, apierr.MapWrite(err)
	}
	return policy, nil
}

// UpdateRequestPolicy updates a policy's approvals + role sources + duration cap. The
// caller's access:policy:update capability at the policy's scope is gated by the
// handler.
func (s *Service) UpdateRequestPolicy(ctx context.Context, id uuid.UUID, requiredApprovals int32, approverRole, requesterRole pgtype.UUID, maxDurationSeconds int64) (sqlc.RequestPolicy, error) {
	policy, err := s.q.UpdateRequestPolicy(ctx, sqlc.UpdateRequestPolicyParams{
		ID:                id,
		RequiredApprovals: requiredApprovals,
		ApproverRoleID:    approverRole,
		RequesterRoleID:   requesterRole,
		MaxDuration:       secondsToInterval(maxDurationSeconds),
	})
	if err != nil {
		return sqlc.RequestPolicy{}, apierr.MapWrite(err)
	}
	return policy, nil
}

// DeleteRequestPolicy removes a request policy by id. The caller's capability
// (access:policy:delete at the policy's scope) is gated by the handler.
func (s *Service) DeleteRequestPolicy(ctx context.Context, id uuid.UUID) error {
	if err := s.q.DeleteRequestPolicy(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// ListRequestPolicies lists all request policies for a role, ordered by (created_at
// DESC, id ASC). The caller's access:policy:read capability (global) is gated by the
// handler. Returns the page rows and an opaque next-page token.
func (s *Service) ListRequestPolicies(ctx context.Context, roleID uuid.UUID, pageSize int32, pageToken string) ([]sqlc.RequestPolicy, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListRequestPoliciesParams{RoleID: roleID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListRequestPolicies(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}

// ListPoliciesForAsset lists the request policies scoped to an asset, ordered by
// (created_at DESC, id ASC). Same global read gate as ListRequestPolicies (in the
// handler).
func (s *Service) ListPoliciesForAsset(ctx context.Context, assetID uuid.UUID, pageSize int32, pageToken string) ([]sqlc.RequestPolicy, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListPoliciesForAssetParams{AssetID: pgconv.UUID(assetID), Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListPoliciesForAsset(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}

// ListPoliciesForGroup lists the request policies a group is a subject of, ordered by
// (created_at DESC, id ASC). Same global read gate as ListRequestPolicies (in the
// handler).
func (s *Service) ListPoliciesForGroup(ctx context.Context, groupID uuid.UUID, pageSize int32, pageToken string) ([]sqlc.RequestPolicy, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListPoliciesForSubjectGroupParams{GroupID: pgconv.UUID(groupID), Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListPoliciesForSubjectGroup(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}

// ResolvePolicy maps a (name, asset scope) to a policy. NotFound if no policy of that
// name is scoped to that asset. The caller's access:policy:read capability at the
// asset scope is gated by the handler. name is expected already normalized
// (lower-cased) by the handler.
func (s *Service) ResolvePolicy(ctx context.Context, name string, assetID uuid.UUID) (sqlc.RequestPolicy, error) {
	p, err := s.q.GetPolicyByNameAndAsset(ctx, sqlc.GetPolicyByNameAndAssetParams{
		Name:         pgconv.Text(name),
		ScopeAssetID: pgconv.UUID(assetID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.RequestPolicy{}, connect.NewError(connect.CodeNotFound, errors.New("no such policy"))
		}
		return sqlc.RequestPolicy{}, connect.NewError(connect.CodeInternal, err)
	}
	return p, nil
}

// AddPolicySubject adds a requester/approver subject to a policy. The caller's
// access:policy:manage-subjects capability at the policy's scope, plus the subject
// validation, are handled by the handler; the service performs the write.
func (s *Service) AddPolicySubject(ctx context.Context, policyID uuid.UUID, kind string, subjUser, subjGroup pgtype.UUID) (sqlc.RequestPolicySubject, error) {
	ps, err := s.q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID:       policyID,
		Kind:           kind,
		SubjectUserID:  subjUser,
		SubjectGroupID: subjGroup,
	})
	if err != nil {
		return sqlc.RequestPolicySubject{}, apierr.MapWrite(err)
	}
	return ps, nil
}

// RemovePolicySubject removes a subject from a policy by id. The caller's capability
// (access:policy:manage-subjects at the policy's scope) is gated by the handler.
func (s *Service) RemovePolicySubject(ctx context.Context, id uuid.UUID) error {
	if err := s.q.RemovePolicySubject(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// ListPolicySubjects lists the subjects attached to a policy, ordered by (created_at
// DESC, id ASC). The caller's access:policy:read capability at the policy's scope is
// gated by the handler. Returns the page rows and an opaque next-page token.
func (s *Service) ListPolicySubjects(ctx context.Context, policyID uuid.UUID, pageSize int32, pageToken string) ([]sqlc.RequestPolicySubject, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListPolicySubjectsParams{PolicyID: policyID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListPolicySubjects(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}
