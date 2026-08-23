package dataplane

import (
	"testing"

	"github.com/google/uuid"
)

// fold replays the debounce-window accumulation exactly as RunAuthzSweeper does at its
// call site: start from (false, nil) and fold each payload with the production
// accumulate, threading the running (full, users) state back in. It returns the final
// (full, users) that runBatch would be handed. Because the escalation logic lives in
// accumulate, a regression there (e.g. dropping the monotonic-full guard) is caught by
// these assertions.
func fold(s *Sweeper, payloads ...string) (bool, map[uuid.UUID]struct{}) {
	full := false
	var users map[uuid.UUID]struct{}
	for _, p := range payloads {
		full, users = s.accumulate(full, users, p)
	}
	return full, users
}

// TestAccumulateFullSweepIsMonotonic pins the invariant that a full sweep, once
// required within a debounce window, is never downgraded to a narrow sweep by a
// subsequent specific-user payload. An empty (or unparseable) payload escalates the
// whole window to a full sweep regardless of ordering.
func TestAccumulateFullSweepIsMonotonic(t *testing.T) {
	s := &Sweeper{}
	u1 := uuid.New()
	u2 := uuid.New()

	t.Run("empty then UUID stays full", func(t *testing.T) {
		full, users := fold(s, "", u1.String())
		if !full {
			t.Fatal("empty-then-UUID must remain a full sweep; a later specific-user payload must not downgrade it")
		}
		if len(users) != 0 {
			t.Fatalf("full sweep must clear the narrow user set, got %d users", len(users))
		}
	})

	t.Run("UUID then empty is full", func(t *testing.T) {
		full, users := fold(s, u1.String(), "")
		if !full {
			t.Fatal("UUID-then-empty must escalate to a full sweep")
		}
		if len(users) != 0 {
			t.Fatalf("full sweep must clear the narrow user set, got %d users", len(users))
		}
	})

	t.Run("unparseable escalates to full", func(t *testing.T) {
		full, _ := fold(s, u1.String(), "not-a-uuid")
		if !full {
			t.Fatal("an unparseable payload must escalate to a full sweep")
		}
	})

	t.Run("empty then multiple UUIDs stays full", func(t *testing.T) {
		full, users := fold(s, "", u1.String(), u2.String())
		if !full {
			t.Fatal("full sweep must survive multiple subsequent specific-user payloads")
		}
		if len(users) != 0 {
			t.Fatalf("full sweep must clear the narrow user set, got %d users", len(users))
		}
	})

	t.Run("UUID then UUID (no empty) stays narrow with both users", func(t *testing.T) {
		full, users := fold(s, u1.String(), u2.String())
		if full {
			t.Fatal("two specific-user payloads with no empty must NOT escalate to a full sweep")
		}
		if len(users) != 2 {
			t.Fatalf("narrow sweep must accumulate the union of affected users, got %d want 2", len(users))
		}
		if _, ok := users[u1]; !ok {
			t.Fatal("narrow user set missing u1")
		}
		if _, ok := users[u2]; !ok {
			t.Fatal("narrow user set missing u2")
		}
	})

	t.Run("single UUID stays narrow", func(t *testing.T) {
		full, users := fold(s, u1.String())
		if full {
			t.Fatal("a single specific-user payload must stay a narrow sweep")
		}
		if len(users) != 1 {
			t.Fatalf("narrow sweep must track the single affected user, got %d want 1", len(users))
		}
	})
}
