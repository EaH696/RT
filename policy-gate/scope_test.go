package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func signed(s Scope, by string) Scope {
	// signed_by is part of the signed body — set it BEFORE hashing, exactly as
	// rt.scope.Scope.sign() does on the Python side.
	s.SignedBy = &by
	c, _ := s.canonical()
	sum := sha256.Sum256([]byte(c))
	sig := hex.EncodeToString(sum[:])
	s.Signature = &sig
	return s
}

func TestPermits(t *testing.T) {
	s := signed(Scope{
		EngagementID:    "T",
		AllowedCIDRs:    []string{"10.0.0.0/24"},
		ExcludedCIDRs:   []string{"10.0.0.9/32"},
		AllowedDomains:  []string{"app.acme.test"},
		ExcludedDomains: []string{},
		MaxRPS:          50,
	}, "esmadi")

	if !s.Verify() {
		t.Fatal("signed scope must verify")
	}
	cases := map[string]bool{
		"10.0.0.5":                     true,
		"https://app.acme.test/login":  true,
		"10.0.0.9":                     false, // excluded wins
		"10.9.9.9":                     false, // not allowed
		"evil.example.com":             false,
	}
	for target, want := range cases {
		if got := s.Permits(target); got != want {
			t.Errorf("Permits(%q)=%v want %v", target, got, want)
		}
	}
}

func TestUnsignedScopeIsDenied(t *testing.T) {
	s := Scope{EngagementID: "T", AllowedCIDRs: []string{"10.0.0.0/24"}}
	if s.Decide("10.0.0.5").Allowed {
		t.Fatal("unsigned scope must never authorize a target")
	}
}
