package auth

import (
	"sync"
	"time"
)

// Throttle applies progressive per-key backoff to failed logins. It is NOT a
// lockout: repeated failures grow a delay and eventually return a hard block
// with Retry-After, but a single success clears the key. Keys are the login
// email and the client IP; the stricter of the two applies.
//
// Entries accumulate until Cleanup is called; nothing here runs it on a
// timer — the caller wires that up. Pass real, non-empty email/ip values:
// an empty string is a valid map key like any other, so blank inputs land
// every caller in one shared bucket and throttle each other.
//
// ponytail: in-memory = per-replica. Move to a shared store (Postgres/Redis)
// when warden runs multi-replica; the HA milestone owns that.
type Throttle struct {
	mu sync.Mutex
	m  map[string]*counter
}

type counter struct {
	failures int
	first    time.Time
}

const (
	throttleWindow    = 15 * time.Minute
	throttleFreeEmail = 5
	throttleHardEmail = 15
	throttleFreeIP    = 20
	throttleHardIP    = 60
	throttleBaseDelay = time.Second
	throttleMaxDelay  = 30 * time.Second
)

// NewThrottle constructs an empty throttle.
func NewThrottle() *Throttle {
	return &Throttle{m: map[string]*counter{}}
}

func (t *Throttle) eval(key string, free, hard int) (time.Duration, bool) {
	c := t.m[key]
	if c == nil {
		return 0, false
	}
	if time.Since(c.first) > throttleWindow {
		// Lazy eviction: Check is not side-effect-free, it also reaps its own
		// stale entry rather than waiting for the next Cleanup sweep.
		delete(t.m, key)
		return 0, false
	}
	if c.failures >= hard {
		return throttleMaxDelay, true
	}
	if c.failures < free {
		return 0, false
	}
	// Clamp the shift itself, not just the result: failures can run up to
	// hard-1, and an unbounded exponent overflows int64 nanoseconds long
	// before it would reach hard. Any exponent past ~6 already saturates
	// throttleMaxDelay, so this bound never changes observable behavior.
	exp := c.failures - free
	if exp > 6 {
		exp = 6
	}
	d := throttleBaseDelay << exp
	if d > throttleMaxDelay {
		d = throttleMaxDelay
	}
	return d, false
}

// Check reports the required pre-verify delay and whether the attempt is hard-
// blocked, taking the stricter of the email and IP counters.
func (t *Throttle) Check(email, ip string) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	de, be := t.eval("e:"+email, throttleFreeEmail, throttleHardEmail)
	di, bi := t.eval("i:"+ip, throttleFreeIP, throttleHardIP)
	return max(de, di), be || bi
}

func (t *Throttle) bump(key string) {
	c := t.m[key]
	now := time.Now()
	if c == nil || now.Sub(c.first) > throttleWindow {
		t.m[key] = &counter{failures: 1, first: now}
		return
	}
	c.failures++
}

// RetryAfter reports how long until a currently-blocked key's window clears,
// taking the longer of the email and IP keys. Returns 0 when nothing is blocked.
func (t *Throttle) RetryAfter(email, ip string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var d time.Duration
	for _, key := range []string{"e:" + email, "i:" + ip} {
		if c := t.m[key]; c != nil {
			if rem := throttleWindow - time.Since(c.first); rem > d {
				d = rem
			}
		}
	}
	return d
}

// Fail records a failed attempt for both keys.
func (t *Throttle) Fail(email, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bump("e:" + email)
	t.bump("i:" + ip)
}

// Success clears both keys.
func (t *Throttle) Success(email, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, "e:"+email)
	delete(t.m, "i:"+ip)
}

// Cleanup drops entries whose window has elapsed. Call periodically.
func (t *Throttle) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, c := range t.m {
		if now.Sub(c.first) > throttleWindow {
			delete(t.m, k)
		}
	}
}
