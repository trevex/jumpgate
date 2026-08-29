package control

import (
	"sort"
	"sync"
	"testing"
)

func TestRegistry(t *testing.T) {
	var mu sync.Mutex
	fired := map[string]int{}
	cancel := func(id string) func() {
		return func() {
			mu.Lock()
			defer mu.Unlock()
			fired[id]++
		}
	}

	r := NewRegistry()
	r.Add("a", cancel("a"))
	r.Add("b", cancel("b"))

	if got := sortedIDs(r); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("LiveIDs = %v, want [a b]", got)
	}

	r.Teardown("a")
	mu.Lock()
	if fired["a"] != 1 {
		t.Fatalf("a cancel fired %d times, want 1", fired["a"])
	}
	mu.Unlock()
	if got := sortedIDs(r); len(got) != 1 || got[0] != "b" {
		t.Fatalf("after Teardown(a), LiveIDs = %v, want [b]", got)
	}

	// Second teardown of a is a no-op, must not fire again.
	r.Teardown("a")
	mu.Lock()
	if fired["a"] != 1 {
		t.Fatalf("a cancel fired %d times after repeat teardown, want 1", fired["a"])
	}
	mu.Unlock()

	// Remove drops b without firing its cancel.
	r.Remove("b")
	if got := sortedIDs(r); len(got) != 0 {
		t.Fatalf("after Remove(b), LiveIDs = %v, want []", got)
	}
	mu.Lock()
	if fired["b"] != 0 {
		t.Fatalf("b cancel fired %d times, want 0 (Remove must not fire)", fired["b"])
	}
	mu.Unlock()

	// Teardown of an unknown id is a no-op.
	r.Teardown("unknown")
}

func sortedIDs(r *Registry) []string {
	ids := r.LiveIDs()
	sort.Strings(ids)
	return ids
}
