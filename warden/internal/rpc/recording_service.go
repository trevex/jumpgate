package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	recordingv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Presigner issues a short-lived download URL for an object key. Satisfied by an
// S3 presign client in production; a fake in tests. A nil Presigner makes the
// download path fail closed (FailedPrecondition).
type Presigner interface {
	PresignGet(ctx context.Context, objectKey string, ttl time.Duration) (url string, expires time.Time, err error)
}

// grantReviewer authorizes grant-scoped recording review: a recording attributed
// to a grant is reviewable by the grant's subject or a potential approver of the
// grant's originating request. Additive to the recording:read capability — the
// handlers consult it only after a cap check denies, and only for grant-attributed
// recordings. Backed by *accessrequest.Service (CanReviewGrant). A nil reviewer
// (defensive) leaves only the recording:read path in force. Fails closed.
type grantReviewer interface {
	CanReviewGrant(ctx context.Context, caller, grantID uuid.UUID) (bool, error)
}

// Default and maximum page sizes for ListRecordings.
const (
	defaultRecordingPageSize = 50
	maxRecordingPageSize     = 200
)

// RecordingServer implements recordingv1connect.RecordingServiceHandler: the
// admin-only API to list/get session recording metadata and issue a short-lived
// presigned download URL. Issuing a download URL is audited post-hoc
// (recording.accessed) via the shared audit Logger, since there is no domain
// transaction to ride along with.
type RecordingServer struct {
	q        *sqlc.Queries
	audit    *audit.Logger
	presign  Presigner // may be nil → download fails closed
	urlTTL   time.Duration
	reviewer grantReviewer // may be nil → only recording:read applies
	capGuard
}

// NewRecordingServer constructs the RecordingService implementation. presign may
// be nil, in which case GetRecordingDownload returns FailedPrecondition. reviewer
// authorizes grant-scoped review (subject or potential approver) on top of the
// recording:read gate; a nil reviewer disables that additive path.
func NewRecordingServer(q *sqlc.Queries, auditLog *audit.Logger, presign Presigner, urlTTL time.Duration, a authz.Authorizer, reviewer grantReviewer) *RecordingServer {
	return &RecordingServer{q: q, audit: auditLog, presign: presign, urlTTL: urlTTL, reviewer: reviewer, capGuard: capGuard{authz: a, q: q}}
}

func toRecordingMsg(r sqlc.SessionRecording) *recordingv1.Recording {
	var startMs, endMs int64
	if r.StartedAt.Valid {
		startMs = r.StartedAt.Time.UnixMilli()
	}
	if r.EndedAt.Valid {
		endMs = r.EndedAt.Time.UnixMilli()
	}
	var grantID string
	if r.GrantID.Valid {
		grantID = uuid.UUID(r.GrantID.Bytes).String()
	}
	return &recordingv1.Recording{
		SessionId:       r.SessionID.String(),
		UserId:          r.UserID.String(),
		AssetId:         r.AssetID.String(),
		Protocol:        r.Protocol,
		Format:          r.Format,
		SizeBytes:       r.SizeBytes,
		Sha256:          r.Sha256,
		Status:          r.Status,
		StartedAtUnixMs: startMs,
		EndedAtUnixMs:   endMs,
		GrantId:         grantID,
	}
}

// ListRecordings lists recordings filtered by the optional user_id/asset_id
// (empty → no filter), newest first (admin only), with keyset pagination on
// (created_at DESC, session_id ASC). session_id is the PK; it is used as the
// tiebreak because session_recordings has no separate `id` column.
func (s *RecordingServer) ListRecordings(ctx context.Context, req *connect.Request[recordingv1.ListRecordingsRequest]) (*connect.Response[recordingv1.ListRecordingsResponse], error) {
	params := sqlc.ListSessionRecordingsParams{}
	if req.Msg.UserId != "" {
		id, err := uuid.Parse(req.Msg.UserId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
		}
		params.UserID = pgtype.UUID{Bytes: id, Valid: true}
	}
	if req.Msg.AssetId != "" {
		id, err := uuid.Parse(req.Msg.AssetId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
		}
		params.AssetID = pgtype.UUID{Bytes: id, Valid: true}
	}
	var grantFilter uuid.UUID
	if req.Msg.GrantId != "" {
		id, err := uuid.Parse(req.Msg.GrantId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad grant_id"))
		}
		grantFilter = id
		params.GrantID = pgtype.UUID{Bytes: id, Valid: true}
	}
	// An asset-scoped filter narrows the required cap to that asset; an unfiltered
	// (fleet-wide) list requires the global recording:read.
	assetFilter := uuidFromPg(params.AssetID)
	scope := authz.GlobalScope()
	if assetFilter != uuid.Nil {
		scope = authz.AssetScope(assetFilter)
	}
	// Authorization: the recording:read capability is the base gate. When the list
	// is scoped to a single grant, a caller who lacks recording:read may still be
	// authorized as the grant's subject or a potential approver (CanReviewGrant).
	// This is strictly additive: the query already filters to grant_id, so no
	// out-of-grant rows can leak. When no grant filter is present, only the
	// capability gate applies (unchanged).
	if capErr := s.requireCap(ctx, "recording:read", scope); capErr != nil {
		if grantFilter == uuid.Nil || s.reviewer == nil {
			return nil, capErr
		}
		caller, ok := auth.UserFromContext(ctx)
		if !ok {
			return nil, capErr
		}
		reviewable, err := s.reviewer.CanReviewGrant(ctx, caller.ID, grantFilter)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !reviewable {
			return nil, capErr
		}
	}
	limit := req.Msg.PageSize
	if limit <= 0 {
		limit = defaultRecordingPageSize
	}
	if limit > maxRecordingPageSize {
		limit = maxRecordingPageSize
	}
	params.Lim = int64(limit)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterSessionID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListSessionRecordings(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &recordingv1.ListRecordingsResponse{}
	for i := range rows {
		out.Recordings = append(out.Recordings, toRecordingMsg(rows[i]))
	}
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.SessionID)
	}
	return connect.NewResponse(out), nil
}

// GetRecording fetches a single recording's metadata by session id (admin only).
func (s *RecordingServer) GetRecording(ctx context.Context, req *connect.Request[recordingv1.GetRecordingRequest]) (*connect.Response[recordingv1.Recording], error) {
	sessionID, err := uuid.Parse(req.Msg.SessionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad session_id"))
	}
	row, err := s.q.GetSessionRecording(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("recording not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.authorizeRecordingRead(ctx, row); err != nil {
		return nil, err
	}
	return connect.NewResponse(toRecordingMsg(row)), nil
}

// authorizeRecordingRead enforces read access to a single recording row: the
// recording:read capability on the recording's asset scope, OR — for a
// grant-attributed recording — grant-scoped review (the grant's subject or a
// potential approver, via CanReviewGrant). Strictly additive: the capability gate
// is always tried first, and the grant-review fallback only applies to recordings
// carrying a grant_id, so an unattributed recording always requires recording:read.
// Returns the existing capability deny error on denial (preserving its code and
// existence-hiding semantics).
func (s *RecordingServer) authorizeRecordingRead(ctx context.Context, row sqlc.SessionRecording) error {
	capErr := s.requireCap(ctx, "recording:read", authz.AssetScope(row.AssetID))
	if capErr == nil {
		return nil
	}
	if !row.GrantID.Valid || s.reviewer == nil {
		return capErr
	}
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return capErr
	}
	reviewable, err := s.reviewer.CanReviewGrant(ctx, caller.ID, uuid.UUID(row.GrantID.Bytes))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if reviewable {
		return nil
	}
	return capErr
}

// GetRecordingDownload issues a short-lived presigned download URL for the
// recorded object (admin only). Issuing the URL is audited (recording.accessed).
// A nil presigner returns FailedPrecondition (recording retrieval not configured).
func (s *RecordingServer) GetRecordingDownload(ctx context.Context, req *connect.Request[recordingv1.GetRecordingRequest]) (*connect.Response[recordingv1.GetRecordingDownloadResponse], error) {
	sessionID, err := uuid.Parse(req.Msg.SessionId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad session_id"))
	}
	row, err := s.q.GetSessionRecording(ctx, sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("recording not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.authorizeRecordingRead(ctx, row); err != nil {
		return nil, err
	}
	if s.presign == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("recording retrieval not configured"))
	}
	url, exp, err := s.presign.PresignGet(ctx, row.ObjectKey, s.urlTTL)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	caller, _ := auth.UserFromContext(ctx)
	details, _ := json.Marshal(map[string]string{"object_key": row.ObjectKey})
	if err := s.audit.Append(ctx, audit.Event{
		Type:    dataplane.EventRecordingAccessed,
		ActorID: caller.ID,
		Subject: "session_recording:" + sessionID.String(),
		Details: details,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&recordingv1.GetRecordingDownloadResponse{
		Url:             url,
		ExpiresAtUnixMs: exp.UnixMilli(),
	}), nil
}
