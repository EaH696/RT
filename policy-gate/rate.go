package main

import (
	"sync"
	"time"
)

// rateLimiter enforces the ROE's max_rps cap (Section 7) as a per-host token
// bucket. Burst capacity is one second's worth of requests; tokens refill
// continuously at max_rps.
//
// This is the LOGICAL cap applied at the policy-gate's /check — it throttles how
// fast the orchestrator can obtain allow decisions, and thus dispatch. The
// PHYSICAL per-connection cap belongs in the sandbox egress proxy (which this
// same limiter can back once egress is wired to a real runtime). Keyed by host
// so one noisy target cannot consume another's budget.
type rateLimiter struct {
	mu      sync.Mutex
	rps     float64
	buckets map[string]*bucket
	now     func() time.Time // injectable for tests
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rps int) *rateLimiter {
	return &rateLimiter{
		rps:     float64(rps),
		buckets: make(map[string]*bucket),
		now:     func() time.Time { return time.Now() },
	}
}

// allow reports whether one request to host may proceed now, consuming a token.
// A non-positive rps means "no cap configured" and always allows.
func (r *rateLimiter) allow(host string) bool {
	if r.rps <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	b := r.buckets[host]
	if b == nil {
		// New host starts with a full bucket (allows an initial burst up to rps).
		b = &bucket{tokens: r.rps, last: now}
		r.buckets[host] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * r.rps
			if b.tokens > r.rps {
				b.tokens = r.rps
			}
			b.last = now
		}
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}
