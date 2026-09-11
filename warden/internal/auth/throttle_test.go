package auth_test

import (
	"fmt"
	"testing"
	"time"

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

func TestThrottlePerIPIndependentOfEmail(t *testing.T) {
	th := auth.NewThrottle()
	const ip = "10.9.9.9"
	// 30 distinct emails, one failure each from the same IP: above the per-IP
	// free count (20) but below the per-IP hard threshold (60).
	for i := 0; i < 30; i++ {
		th.Fail(fmt.Sprintf("user%d@x", i), ip)
	}
	// A brand-new email (zero failures of its own) still inherits the IP delay.
	if d, blocked := th.Check("fresh@x", ip); blocked || d == 0 {
		t.Fatalf("expected IP-driven delay for fresh email: d=%v blocked=%v", d, blocked)
	}
	// Push the IP counter past its hard threshold (60).
	for i := 30; i < 61; i++ {
		th.Fail(fmt.Sprintf("user%d@x", i), ip)
	}
	if _, blocked := th.Check("another-fresh@x", ip); !blocked {
		t.Fatal("expected IP-driven hard block for a fresh email")
	}
}

func TestThrottleRetryAfter(t *testing.T) {
	th := auth.NewThrottle()
	const email, ip = "retry@x", "10.0.0.2"

	if d := th.RetryAfter(email, ip); d != 0 {
		t.Fatalf("fresh key: RetryAfter = %v, want 0", d)
	}

	for i := 0; i < 15; i++ {
		th.Fail(email, ip)
	}
	if _, blocked := th.Check(email, ip); !blocked {
		t.Fatal("expected hard block")
	}
	d := th.RetryAfter(email, ip)
	if d <= 0 || d > 15*time.Minute {
		t.Fatalf("blocked key: RetryAfter = %v, want (0, 15m]", d)
	}
}
