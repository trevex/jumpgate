package dataplane

import "testing"

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
