// Package ratelimit provides a per-identity token-bucket rate limiter with
// automatic eviction of idle entries.
//
// Each Ziti identity gets its own [golang.org/x/time/rate.Limiter]. Entries
// that have not been accessed for longer than the configured idle TTL are
// removed by a background goroutine, bounding memory growth over long uptimes.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Map is a thread-safe collection of per-identity rate limiters.
// The zero value is not usable; create one with [New].
type Map struct {
	mu      sync.Mutex
	entries map[string]*entry

	// Limiter parameters — set once at construction.
	r     rate.Limit // tokens per second
	burst int

	// idleTTL is how long an entry may go unused before eviction.
	idleTTL time.Duration
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New creates a Map that allows rps tokens per second per identity with a
// burst allowance of burst tokens. Entries that have had no activity for
// idleTTL are evicted by a background goroutine. The goroutine runs until
// stopCh is closed (pass a channel you close on shutdown, or a nil channel
// to never stop — suitable for long-running services where the process exits
// instead).
//
// rps must be > 0 and burst must be >= 1.
func New(rps float64, burst int, idleTTL time.Duration, stopCh <-chan struct{}) *Map {
	m := &Map{
		entries: make(map[string]*entry),
		r:       rate.Limit(rps),
		burst:   burst,
		idleTTL: idleTTL,
	}

	// Eviction goroutine: sweep every half-idleTTL.
	go func() {
		ticker := time.NewTicker(idleTTL / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.evict()
			case <-stopCh:
				return
			}
		}
	}()

	return m
}

// Allow reports whether the identity is allowed to make a request right now.
// It creates a new limiter for first-time callers.
func (m *Map) Allow(identity string) bool {
	m.mu.Lock()
	e, ok := m.entries[identity]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(m.r, m.burst)}
		m.entries[identity] = e
	}
	e.lastSeen = time.Now()
	allowed := e.limiter.Allow()
	m.mu.Unlock()
	return allowed
}

// evict removes entries that have been idle for longer than idleTTL.
func (m *Map) evict() {
	cutoff := time.Now().Add(-m.idleTTL)
	m.mu.Lock()
	for id, e := range m.entries {
		if e.lastSeen.Before(cutoff) {
			delete(m.entries, id)
		}
	}
	m.mu.Unlock()
}
