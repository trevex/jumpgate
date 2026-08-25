package audit_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestAppendAndVerify(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := log.Append(ctx, audit.Event{Type: "test.event", Subject: "asset:x", Details: []byte(`{"i":1}`)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify intact chain: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()
	_ = log.Append(ctx, audit.Event{Type: "a", Subject: "s1"})
	_ = log.Append(ctx, audit.Event{Type: "b", Subject: "s2"})
	_ = log.Append(ctx, audit.Event{Type: "c", Subject: "s3"})

	if err := log.Verify(ctx); err != nil {
		t.Fatalf("pre-tamper verify: %v", err)
	}
	// tamper: mutate a subject in the middle without fixing the hash chain
	if _, err := pool.Exec(ctx, `UPDATE audit_log SET subject = 'HACKED' WHERE seq = (SELECT min(seq)+1 FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(ctx); err == nil {
		t.Fatal("verify should FAIL after tampering, but passed")
	}
}

func TestAppendWithActor(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()
	// use a random actor uuid.Nil is fine too; here nil (no FK requirement)
	if err := log.Append(ctx, audit.Event{Type: "login", ActorID: uuid.Nil, Subject: "user:x"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestChainSurvivesActorDeletion(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "actor@x", DisplayName: "Actor"})
	if err != nil {
		t.Fatal(err)
	}
	log := audit.New(pool)
	if err := log.Append(ctx, audit.Event{Type: "login", ActorID: u.ID, Subject: "user:actor"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(ctx, audit.Event{Type: "logout", ActorID: u.ID, Subject: "user:actor"}); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("pre-deletion verify: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("chain must remain verifiable after actor deletion: %v", err)
	}
}
