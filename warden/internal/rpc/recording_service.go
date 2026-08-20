package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	recordingv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// Presigner issues a short-lived download URL for an object key. Satisfied by an
// S3 presign client in production; a fake in tests. A nil Presigner makes the
// download path fail closed (FailedPrecondition).
type Presigner interface {
	PresignGet(ctx context.Context, objectKey string, ttl time.Duration) (url string, expires time.Time, err error)
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
	q       *gen.Queries
	audit   *audit.Logger
	presign Presigner // may be nil → download fails closed
	urlTTL  time.Duration
	capGuard
}

// NewRecordingServer constructs the RecordingService implementation. presign may
// be nil, in which case GetRecordingDownload returns FailedPrecondition.
func NewRecordingServer(q *gen.Queries, auditLog *audit.Logger, presign Presigner, urlTTL time.Duration, a authz.Authorizer) *RecordingServer {
	return &RecordingServer{q: q, audit: auditLog, presign: presign, urlTTL: urlTTL, capGuard: capGuard{authz: a, q: q}}
}

func toRecordingMsg(r gen.SessionRecording) *recordingv1.Recording {
	var startMs, endMs int64
	if r.StartedAt.Valid {
		startMs = r.StartedAt.Time.UnixMilli()
	}
	if r.EndedAt.Valid {
		endMs = r.EndedAt.Time.UnixMilli()
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
	}
}

// ListRecordings lists recordings filtered by the optional user_id/asset_id
// (empty → no filter), newest first (admin only).
func (s *RecordingServer) ListRecordings(ctx context.Context, req *connect.Request[recordingv1.ListRecordingsRequest]) (*connect.Response[recordingv1.ListRecordingsResponse], error) {
	userFilter := uuid.Nil
	if req.Msg.UserId != "" {
		id, err := uuid.Parse(req.Msg.UserId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
		}
		userFilter = id
	}
	assetFilter := uuid.Nil
	if req.Msg.AssetId != "" {
		id, err := uuid.Parse(req.Msg.AssetId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
		}
		assetFilter = id
	}
	// An asset-scoped filter narrows the required cap to that asset; an unfiltered
	// (fleet-wide) list requires the global recording:read.
	scope := authz.GlobalScope()
	if assetFilter != uuid.Nil {
		scope = authz.AssetScope(assetFilter)
	}
	if err := s.requireCap(ctx, "recording:read", scope); err != nil {
		return nil, err
	}
	limit := req.Msg.PageSize
	if limit <= 0 {
		limit = defaultRecordingPageSize
	}
	if limit > maxRecordingPageSize {
		limit = maxRecordingPageSize
	}
	rows, err := s.q.ListSessionRecordings(ctx, gen.ListSessionRecordingsParams{
		Column1: userFilter,
		Column2: assetFilter,
		Limit:   limit,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &recordingv1.ListRecordingsResponse{}
	for i := range rows {
		out.Recordings = append(out.Recordings, toRecordingMsg(rows[i]))
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
	if err := s.requireCap(ctx, "recording:read", authz.AssetScope(row.AssetID)); err != nil {
		return nil, err
	}
	return connect.NewResponse(toRecordingMsg(row)), nil
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
	if err := s.requireCap(ctx, "recording:read", authz.AssetScope(row.AssetID)); err != nil {
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
