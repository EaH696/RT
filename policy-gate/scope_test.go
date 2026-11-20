package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// signWith signs a scope with an Ed25519 seed exactly as rt.scope.Scope.sign()
// does on the Python side: set signed_by/sig_alg/public_key into the signed
// body first, then sign the canonical form.
func signWith(s Scope, by string, seed []byte) (Scope, string) {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	alg := "ed25519"
	s.SignedBy = &by
	s.SigAlg = &alg
	s.PublicKey = &pub
	c, _ := s.canonical()
	sig := hex.EncodeToString(ed25519.Sign(priv, []byte(c)))
	s.Signature = &sig
	return s, pub
}

func sampleScope() Scope {
	return Scope{
		EngagementID:    "T",
		AllowedCIDRs:    []string{"10.0.0.0/24"},
		ExcludedCIDRs:   []string{"10.0.0.9/32"},
		AllowedDomains:  []string{"app.acme.test"},
		ExcludedDomains: []string{},
		MaxRPS:          50,
	}
}

func TestPermits(t *testing.T) {
	seed := make([]byte, 32) // deterministic test key
	s, _ := signWith(sampleScope(), "esmadi", seed)

	if !s.Verify() {
		t.Fatal("signed scope must verify cryptographically")
	}
	cases := map[string]bool{
		"10.0.0.5":                    true,
		"https://app.acme.test/login": true,
		"10.0.0.9":                    false, // excluded wins
		"10.9.9.9":                    false, // not allowed
		"evil.example.com":            false,
	}
	for target, want := range cases {
		if got := s.Permits(target); got != want {
			t.Errorf("Permits(%q)=%v want %v", target, got, want)
		}
	}
}

func TestTrustAnchor(t *testing.T) {
	seed := make([]byte, 32)
	s, pub := signWith(sampleScope(), "esmadi", seed)

	// Cryptographically valid but key not trusted -> not authorized.
	if s.WithTrust(map[string]bool{"deadbeef": true}).Decide("10.0.0.5").Allowed {
		t.Fatal("untrusted signing key must not authorize")
	}
	// Key in the trust store -> authorized.
	if !s.WithTrust(map[string]bool{pub: true}).Decide("10.0.0.5").Allowed {
		t.Fatal("trusted key + in-scope target must be allowed")
	}
	// Empty trust store -> nothing authorized.
	if s.WithTrust(nil).Decide("10.0.0.5").Allowed {
		t.Fatal("empty trust store must authorize nothing")
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	seed := make([]byte, 32)
	s, pub := signWith(sampleScope(), "esmadi", seed)
	// Flip an in-scope CIDR after signing; signature must no longer verify.
	s.AllowedCIDRs = []string{"0.0.0.0/0"}
	if s.WithTrust(map[string]bool{pub: true}).Decide("8.8.8.8").Allowed {
		t.Fatal("tampered scope must not verify (would have widened scope)")
	}
}

func TestUnsignedScopeIsDenied(t *testing.T) {
	s := sampleScope()
	if s.Decide("10.0.0.5").Allowed {
		t.Fatal("unsigned scope must never authorize a target")
	}
}
