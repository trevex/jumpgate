package frontdoor

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
)

// fakeUploader captures the last uploaded body + key.
type fakeUploader struct {
	mu   sync.Mutex
	key  string
	body []byte
}

func (u *fakeUploader) Put(_ context.Context, key string, body []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.key = key
	u.body = append([]byte(nil), body...)
	return nil
}

// fakeConn is a minimal net.Conn usable only as a map key.
type fakeConn struct{ net.Conn }

func TestRecorderPerConnectionLifecycle(t *testing.T) {
	up := &fakeUploader{}
	ended := make(chan SessionEnd, 4)
	m := NewRecorder(up, "broker-0", ended)

	conn := &fakeConn{}
	ctx := m.ConnContext(context.Background(), conn)

	claims := sessiontoken.Claims{
		SessionID: uuid.New(),
		UserID:    uuid.New(),
		AssetID:   uuid.New(),
		Groups:    []string{"developers", "system:masters"},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)

	if err := m.tap(ctx, claims, req, 200); err != nil {
		t.Fatalf("tap 1: %v", err)
	}
	if err := m.tap(ctx, claims, req, 200); err != nil {
		t.Fatalf("tap 2: %v", err)
	}

	m.ConnState(conn, http.StateClosed)

	var se SessionEnd
	select {
	case se = <-ended:
	default:
		t.Fatal("no SessionEnd reported")
	}
	if se.Report.Status != "completed" {
		t.Fatalf("status = %q, want completed", se.Report.Status)
	}
	if se.RecordingID == "" || se.UserID != claims.UserID.String() ||
		se.AssetID != claims.AssetID.String() || se.SessionID != claims.SessionID.String() {
		t.Fatalf("SessionEnd identity not populated: %+v", se)
	}
	up.mu.Lock()
	key, body := up.key, up.body
	up.mu.Unlock()
	if !strings.HasPrefix(key, "recordings/kubernetes/") {
		t.Fatalf("object key = %q", key)
	}
	// header + 2 events = 3 NDJSON lines (trailing newline → drop empty tail).
	lines := bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("NDJSON lines = %d, want 3\n%s", len(lines), body)
	}
}

// tap without a ConnContext-attached handle must fail closed.
func TestTapFailsClosedWithoutConn(t *testing.T) {
	m := NewRecorder(&fakeUploader{}, "broker-0", make(chan SessionEnd, 1))
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	if err := m.tap(context.Background(), sessiontoken.Claims{}, req, 200); err != errNoRecording {
		t.Fatalf("err = %v, want errNoRecording", err)
	}
}
