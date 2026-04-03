package ratelimit_test

import (
	"testing"
	"time"

	"github.com/edwardm/ziti-ssh/internal/ratelimit"
)

// neverStop returns a channel that is never closed, suitable for tests that
// manage the Map lifetime via the test boundary instead of via the channel.
func neverStop() <-chan struct{} {
	return make(chan struct{})
}

func TestAllow_WithinBurst(t *testing.T) {
	// 1 request per minute, burst of 3: the first 3 requests must all be
	// allowed (consumed from the burst bucket).
	m := ratelimit.New(1.0/60.0, 3, 10*time.Minute, neverStop())

	for i := 0; i < 3; i++ {
		if !m.Allow("alice") {
			t.Fatalf("request %d should be allowed (within burst)", i+1)
		}
	}
}

func TestAllow_ExceedsBurst(t *testing.T) {
	// 1 request per minute, burst of 3: the 4th immediate request must be
	// denied — the bucket is empty and the refill rate is very slow.
	m := ratelimit.New(1.0/60.0, 3, 10*time.Minute, neverStop())

	for i := 0; i < 3; i++ {
		m.Allow("alice")
	}

	if m.Allow("alice") {
		t.Fatal("4th request should be denied (burst exhausted)")
	}
}

func TestAllow_PerIdentityIsolation(t *testing.T) {
	// Exhausting alice's bucket must not affect bob's bucket.
	m := ratelimit.New(1.0/60.0, 1, 10*time.Minute, neverStop())

	m.Allow("alice") // consumes alice's single burst token

	if m.Allow("alice") {
		t.Fatal("alice's 2nd request should be denied")
	}
	if !m.Allow("bob") {
		t.Fatal("bob should still be allowed (independent bucket)")
	}
}

func TestAllow_EvictsIdleEntries(t *testing.T) {
	// Use a very short idle TTL and a fast eviction sweep so the test
	// completes quickly.
	const idleTTL = 100 * time.Millisecond
	stop := make(chan struct{})
	defer close(stop)

	m := ratelimit.New(1.0/60.0, 1, idleTTL, stop)

	// Exhaust alice's burst.
	m.Allow("alice")
	if m.Allow("alice") {
		t.Fatal("alice should be rate-limited before eviction")
	}

	// Wait long enough for the eviction goroutine to remove alice's entry
	// (sweep runs every idleTTL/2 = 50ms).
	time.Sleep(3 * idleTTL)

	// After eviction, alice's entry is gone. A new Allow call creates a fresh
	// limiter with a full burst bucket, so it must succeed.
	if !m.Allow("alice") {
		t.Fatal("alice's entry should have been evicted; fresh limiter should allow the request")
	}
}
