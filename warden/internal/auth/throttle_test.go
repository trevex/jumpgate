package auth_test

import (
	"testing"

	"github.com/trevex/jumpgate/warden/internal/auth"
)

func TestThrottleProgressive(t *testing.T) {
	th := auth.NewThrottle()
	const email, ip = "u@x", "10.0.0.1"

	// Free attempts: no delay, not blocked.
	for i := 0; i < 5; i++ {
		if d, blocked := th.Check(email, ip); blocked || d != 0 {
			t.Fatalf("attempt %d: d=%v blocked=%v", i, d, blocked)
		}
		th.Fail(email, ip)
	}
	// Now delayed but not blocked.
	if d, blocked := th.Check(email, ip); blocked || d == 0 {
		t.Fatalf("expected delay, got d=%v blocked=%v", d, blocked)
	}
	// Drive to the hard threshold.
	for i := 0; i < 15; i++ {
		th.Fail(email, ip)
	}
	if _, blocked := th.Check(email, ip); !blocked {
		t.Fatal("expected hard block")
	}
	// Success clears the counter.
	th.Success(email, ip)
	if d, blocked := th.Check(email, ip); blocked || d != 0 {
		t.Fatalf("after success: d=%v blocked=%v", d, blocked)
	}
}
