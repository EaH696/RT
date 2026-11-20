package main

import (
	"testing"
	"time"
)

func TestRateLimiterCapsAndRefills(t *testing.T) {
	clock := time.Unix(0, 0)
	r := newRateLimiter(3) // 3 rps
	r.now = func() time.Time { return clock }

	// full bucket: first 3 allowed, 4th denied (same instant)
	for i := 0; i < 3; i++ {
		if !r.allow("10.0.0.5") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if r.allow("10.0.0.5") {
		t.Fatal("4th request in the same second must be denied")
	}
	// another host has its own budget
	if !r.allow("10.0.0.6") {
		t.Fatal("a different host must not share the first host's budget")
	}
	// after ~0.4s, ~1 token has refilled (3 rps * 0.4s = 1.2)
	clock = clock.Add(400 * time.Millisecond)
	if !r.allow("10.0.0.5") {
		t.Fatal("a token should have refilled after 0.4s")
	}
	if r.allow("10.0.0.5") {
		t.Fatal("only one token should have refilled")
	}
}

func TestRateLimiterUnlimitedWhenZero(t *testing.T) {
	r := newRateLimiter(0)
	for i := 0; i < 100; i++ {
		if !r.allow("h") {
			t.Fatal("max_rps=0 means no cap; all requests allowed")
		}
	}
}
