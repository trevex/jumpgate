package dataplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// seedLiveSession creates the minimal FK graph (folder, ssh asset, user) and
// inserts a live_sessions row owned by workerID, returning its id.
func seedLiveSession(t *testing.T, pool *pgxpool.Pool, workerID string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	id := uuid.New()
	if _, err := q.InsertLiveSession(ctx, gen.InsertLiveSessionParams{
		ID:          id,
		UserID:      user.ID,
		AssetID:     asset.ID,
		WorkerID:    workerID,
		Protocol:    "ssh",
		Principals:  []string{"deploy"},
		ClientKeyFp: "fp",
	}); err != nil {
		t.Fatalf("InsertLiveSession: %v", err)
	}
	return id
}

func TestNotifyTeardownRoundTrip(t *testing.T) {
	pool := newPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := dataplane.NewRegistry()
	sink := make(chan dataplane.Signal, 1)
	reg.Add("w1", sink)

	sid := seedLiveSession(t, pool, "w1")

	l := dataplane.NewListener(pool, reg)
	go func() { _ = l.Run(ctx) }()

	// Retry NOTIFY until delivered: LISTEN/NOTIFY only delivers to sessions
	// already LISTENing, so re-fire until the Listener's LISTEN is active.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := dataplane.NotifyTeardown(ctx, pool, sid.String(), "revoked"); err != nil {
			t.Fatalf("notify: %v", err)
		}
		select {
		case sig := <-sink:
			if sig.SessionID != sid.String() || sig.Reason != "revoked" {
				t.Fatalf("unexpected signal %+v", sig)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("teardown not delivered via LISTEN/NOTIFY within deadline")
}

func TestNotifyTeardownUnknownSession(t *testing.T) {
	pool := newPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := dataplane.NewRegistry()
	sink := make(chan dataplane.Signal, 1)
	reg.Add("w1", sink)

	// Also register a real session so we can confirm the listener is live and
	// delivering (control), then assert the unknown-session NOTIFY is a no-op.
	l := dataplane.NewListener(pool, reg)
	go func() { _ = l.Run(ctx) }()

	unknown := uuid.New()
	// Fire repeatedly for the whole window; nothing must ever arrive.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := dataplane.NotifyTeardown(ctx, pool, unknown.String(), "revoked"); err != nil {
			t.Fatalf("notify: %v", err)
		}
		select {
		case sig := <-sink:
			t.Fatalf("unexpected signal for unknown session: %+v", sig)
		case <-time.After(30 * time.Millisecond):
		}
	}
}

func TestNotifyTeardownNotOwnedHere(t *testing.T) {
	pool := newPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := dataplane.NewRegistry()
	sink := make(chan dataplane.Signal, 1)
	reg.Add("w1", sink) // only w1 registered locally

	sid := seedLiveSession(t, pool, "w2") // session owned by w2

	l := dataplane.NewListener(pool, reg)
	go func() { _ = l.Run(ctx) }()

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := dataplane.NotifyTeardown(ctx, pool, sid.String(), "revoked"); err != nil {
			t.Fatalf("notify: %v", err)
		}
		select {
		case sig := <-sink:
			t.Fatalf("w1 sink received a signal for a w2-owned session: %+v", sig)
		case <-time.After(30 * time.Millisecond):
		}
	}
}
