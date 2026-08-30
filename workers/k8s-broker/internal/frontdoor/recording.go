package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/k8spath"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/record"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
)

var errNoRecording = errors.New("frontdoor: recording unavailable")

// SessionEnd is a finished per-connection recording, reported to warden. The
// RecordingID is the ledger row PK (per-connection); SessionID is the token jti.
type SessionEnd struct {
	RecordingID string
	Report      record.Report
	UserID      string
	AssetID     string
	SessionID   string
}

type connKeyT struct{}

type connRec struct {
	once      sync.Once
	rec       *record.Recorder
	recID     string
	userID    string
	assetID   string
	sessionID string
}

// Recorder manages per-connection recorders for the front door.
type Recorder struct {
	up       record.Uploader
	brokerID string
	ended    chan<- SessionEnd
	mu       sync.Mutex
	byConn   map[net.Conn]*connRec
}

// NewRecorder builds a front-door recorder that uploads via up and reports each
// finished per-connection recording on ended. A nil up disables recording, which
// the fail-closed tap turns into a per-request refusal.
func NewRecorder(up record.Uploader, brokerID string, ended chan<- SessionEnd) *Recorder {
	return &Recorder{up: up, brokerID: brokerID, ended: ended, byConn: map[net.Conn]*connRec{}}
}

// ConnContext attaches a fresh per-connection handle (wire as http.Server.ConnContext).
func (m *Recorder) ConnContext(ctx context.Context, c net.Conn) context.Context {
	cr := &connRec{}
	m.mu.Lock()
	m.byConn[c] = cr
	m.mu.Unlock()
	return context.WithValue(ctx, connKeyT{}, cr)
}

// ConnState finishes + reports on connection close (wire as http.Server.ConnState).
func (m *Recorder) ConnState(c net.Conn, st http.ConnState) {
	if st != http.StateClosed && st != http.StateHijacked {
		return
	}
	m.mu.Lock()
	cr := m.byConn[c]
	delete(m.byConn, c)
	m.mu.Unlock()
	if cr == nil || cr.rec == nil {
		return
	}
	upCtx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 15*time.Second)
	defer cancel()
	rep := cr.rec.Finish(upCtx, time.Now().UnixMilli())
	select {
	case m.ended <- SessionEnd{RecordingID: cr.recID, Report: rep, UserID: cr.userID, AssetID: cr.assetID, SessionID: cr.sessionID}:
	default: // best-effort, like pg-proxy: drop under backpressure rather than block the conn
	}
}

// tap records one API request. Lazily builds the recorder on first use (needs
// claims). Returns an error to fail the request closed if recording is impossible.
func (m *Recorder) tap(ctx context.Context, claims sessiontoken.Claims, req *http.Request, code int) error {
	if m.up == nil {
		return errNoRecording // recording disabled → refuse every request (fail-closed)
	}
	cr, _ := ctx.Value(connKeyT{}).(*connRec)
	if cr == nil {
		return errNoRecording
	}
	cr.once.Do(func() {
		cr.recID = uuid.NewString()
		cr.userID = claims.UserID.String()
		cr.assetID = claims.AssetID.String()
		cr.sessionID = claims.SessionID.String()
		now := time.Now()
		cr.rec = record.New(m.up, objectKey(cr.recID, now), record.Header{
			V: 1, Kind: "k8s", SessionID: cr.sessionID, StartedAtMS: now.UnixMilli(),
		})
	})
	info := k8spath.Parse(req.Method, req.URL.Path, req.URL.RawQuery)
	return cr.rec.Tap(record.Event{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"verb":      info.Verb,
		"path":      req.URL.Path,
		"resource":  info.Resource,
		"namespace": info.Namespace,
		"name":      info.Name,
		"user":      cr.userID,
		"groups":    claims.Groups,
		"code":      code,
	})
}

// objectKey = recordings/kubernetes/<yyyy>/<mm>/<dd>/<recID>.ndjson
func objectKey(recID string, at time.Time) string {
	u := at.UTC()
	return fmt.Sprintf("recordings/kubernetes/%04d/%02d/%02d/%s.ndjson", u.Year(), int(u.Month()), u.Day(), recID)
}
