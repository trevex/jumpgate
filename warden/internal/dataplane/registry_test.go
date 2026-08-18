package dataplane

import (
	"testing"
	"time"
)

func TestRegistryAddPushRemove(t *testing.T) {
	r := NewRegistry()
	ch := make(chan Signal, 1)
	r.Add("w1", ch)

	if !r.Connected("w1") {
		t.Fatal("w1 should be connected after Add")
	}
	if !r.Push("w1", Signal{SessionID: "s1", Reason: "revoked"}) {
		t.Fatal("Push to connected worker should report delivered")
	}
	select {
	case sig := <-ch:
		if sig.SessionID != "s1" || sig.Reason != "revoked" {
			t.Fatalf("unexpected signal: %+v", sig)
		}
	default:
		t.Fatal("expected signal on sink")
	}

	r.Remove("w1", ch)
	if r.Connected("w1") {
		t.Fatal("w1 should not be connected after Remove")
	}
	if r.Push("w1", Signal{SessionID: "s2"}) {
		t.Fatal("Push after Remove should report not delivered")
	}
}

func TestRegistryPushUnknownWorker(t *testing.T) {
	r := NewRegistry()
	if r.Push("nope", Signal{SessionID: "s1"}) {
		t.Fatal("Push to unknown worker should report not delivered")
	}
	if r.Connected("nope") {
		t.Fatal("unknown worker should not be connected")
	}
}

func recvRoster(t *testing.T, ch <-chan RosterEvent) RosterEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for roster event")
		return RosterEvent{}
	}
}

func TestRegistryRosterFeed(t *testing.T) {
	r := NewRegistry()
	r.SetWorkerMeta("w1", WorkerMeta{Protocol: "ssh", Address: "10.0.0.1:9000", Capacity: 10})

	sub, cancel := r.SubscribeRoster()
	defer cancel()

	// snapshot: w1 present at subscribe time
	ev := recvRoster(t, sub)
	if ev.Kind != RosterAdded || ev.Worker.WorkerID != "w1" || ev.Worker.Address != "10.0.0.1:9000" {
		t.Fatalf("snapshot: %+v", ev)
	}
	// a new worker → Added delta
	r.SetWorkerMeta("w2", WorkerMeta{Protocol: "ssh", Address: "10.0.0.2:9000", Capacity: 5})
	ev = recvRoster(t, sub)
	if ev.Kind != RosterAdded || ev.Worker.WorkerID != "w2" {
		t.Fatalf("added: %+v", ev)
	}
	// removal → Removed delta
	r.ClearWorkerMeta("w2")
	ev = recvRoster(t, sub)
	if ev.Kind != RosterRemoved || ev.Worker.WorkerID != "w2" {
		t.Fatalf("removed: %+v", ev)
	}
}

func TestSubscribeRosterCancel(t *testing.T) {
	t.Helper()
	r := NewRegistry()
	sub, cancel := r.SubscribeRoster()
	cancel()
	// After cancel, SetWorkerMeta must not block and the channel is closed/idle.
	r.SetWorkerMeta("w9", WorkerMeta{Protocol: "ssh", Address: "x:1", Capacity: 1})
	// draining a closed/idle channel should not hang (best-effort: non-blocking check)
	select {
	case <-sub:
	case <-time.After(200 * time.Millisecond):
	}
}
