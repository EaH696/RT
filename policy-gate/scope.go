// Package main implements RT's policy-gate: the authoritative enforcement of
// the signed engagement scope. Every tool call the orchestrator wants to run
// is validated here BEFORE dispatch (logical check), and the gate also fronts
// the only network egress the sandbox has (physical check, see proxy.go stub).
//
// This is deliberately a small, compiled, LLM-free component. The Python
// orchestrator has its own scope check (rt.scope) for speed and early
// rejection, but THIS is the one that must hold even if an agent is confused
// or compromised. Defense in depth.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Scope mirrors rt/scope.py. Keep the JSON field names in sync with the Python
// side — both read the same signed scope.json on the appliance.
type Scope struct {
	EngagementID   string   `json:"engagement_id"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	AllowedDomains []string `json:"allowed_domains"`
	ExcludedCIDRs  []string `json:"excluded_cidrs"`
	ExcludedDomains []string `json:"excluded_domains"`
	WindowStart    *string  `json:"window_start"`
	WindowEnd      *string  `json:"window_end"`
	MaxRPS         int      `json:"max_rps"`
	SignedBy       *string  `json:"signed_by"`
	SigAlg         *string  `json:"sig_alg"`
	PublicKey      *string  `json:"public_key"`
	Signature      *string  `json:"signature"`

	// trust is the provisioned set of accepted operator public keys (hex). Set
	// at load time from the gate's trust store; never serialized. Decide() uses
	// it so an unknown signing key cannot authorize an engagement.
	trust map[string]bool
}

// WithTrust returns a copy of the scope bound to a trust store.
func (s Scope) WithTrust(trust map[string]bool) Scope {
	s.trust = trust
	return s
}

// canonical serializes everything except the signature, matching the Python
// signer's sort_keys=True JSON. Any divergence here means a scope signed by the
// operator would fail verification — keep the two implementations identical.
func (s Scope) canonical() (string, error) {
	m := map[string]any{
		"engagement_id":    s.EngagementID,
		"allowed_cidrs":    nilSliceToEmpty(s.AllowedCIDRs),
		"allowed_domains":  nilSliceToEmpty(s.AllowedDomains),
		"excluded_cidrs":   nilSliceToEmpty(s.ExcludedCIDRs),
		"excluded_domains": nilSliceToEmpty(s.ExcludedDomains),
		"window_start":     s.WindowStart,
		"window_end":       s.WindowEnd,
		"max_rps":          s.MaxRPS,
		"signed_by":        s.SignedBy,
		"sig_alg":          s.SigAlg,
		"public_key":       s.PublicKey,
	}
	b, err := marshalSorted(m)
	return string(b), err
}

// Verify checks the ROE's Ed25519 signature against the embedded public key.
// This proves authenticity but NOT authorization — use VerifyTrusted on the
// appliance so an unknown key cannot authorize an engagement. A scope that
// does not verify must never be used.
func (s Scope) Verify() bool {
	if s.Signature == nil || s.PublicKey == nil || s.SigAlg == nil || *s.SigAlg != "ed25519" {
		return false
	}
	pub, err := hex.DecodeString(*s.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(*s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	c, err := s.canonical()
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(c), sig)
}

// VerifyTrusted additionally requires the signing key to be in the provisioned
// trust store (operator public keys, hex). This is the authorization anchor:
// a cryptographically valid signature from an unknown key is still rejected.
func (s Scope) VerifyTrusted(trust map[string]bool) bool {
	if !s.Verify() {
		return false
	}
	if len(trust) == 0 {
		return false // no trusted keys configured => nothing is authorized
	}
	return s.PublicKey != nil && trust[*s.PublicKey]
}

// Permits reports whether target (IP, host, or URL host) is in scope.
// Exclusions always win.
func (s Scope) Permits(target string) bool {
	host := hostOf(target)
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range s.ExcludedCIDRs {
			if cidrContains(c, ip) {
				return false
			}
		}
		for _, c := range s.AllowedCIDRs {
			if cidrContains(c, ip) {
				return true
			}
		}
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range s.ExcludedDomains {
		if domainMatch(h, d) {
			return false
		}
	}
	for _, d := range s.AllowedDomains {
		if domainMatch(h, d) {
			return true
		}
	}
	return false
}

// Decision is the gate's answer for one requested target.
type Decision struct {
	Target  string `json:"target"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func (s Scope) Decide(target string) Decision {
	return s.DecideAt(target, time.Now().UTC())
}

// DecideAt is Decide with an explicit clock, for testability. Order matters:
// signature/trust first, then the ROE time window, then target scope.
func (s Scope) DecideAt(target string, now time.Time) Decision {
	if !s.VerifyTrusted(s.trust) {
		return Decision{target, false, "scope signature invalid or signing key not trusted"}
	}
	if ok, reason := s.withinWindow(now); !ok {
		return Decision{target, false, reason}
	}
	if s.Permits(target) {
		return Decision{target, true, "in scope"}
	}
	return Decision{target, false, fmt.Sprintf("%q out of scope for %s", target, s.EngagementID)}
}

// withinWindow enforces the ROE testing window (Section 3 of the engagement
// authorization). A malformed window fails CLOSED — a safety control that
// cannot be parsed must not silently allow testing.
func (s Scope) withinWindow(now time.Time) (bool, string) {
	if s.WindowStart != nil && *s.WindowStart != "" {
		t, err := time.Parse(time.RFC3339, *s.WindowStart)
		if err != nil {
			return false, "engagement window_start is malformed (fix scope.json)"
		}
		if now.Before(t) {
			return false, "engagement testing window has not started yet"
		}
	}
	if s.WindowEnd != nil && *s.WindowEnd != "" {
		t, err := time.Parse(time.RFC3339, *s.WindowEnd)
		if err != nil {
			return false, "engagement window_end is malformed (fix scope.json)"
		}
		if now.After(t) {
			return false, "engagement testing window has ended"
		}
	}
	return true, ""
}

func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.Index(t, "/"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	if strings.HasPrefix(t, "[") { // [ipv6]:port
		if i := strings.Index(t, "]"); i >= 0 {
			return t[1:i]
		}
	}
	if strings.Count(t, ":") == 1 {
		t = strings.Split(t, ":")[0]
	}
	return t
}

func cidrContains(cidr string, ip net.IP) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

func domainMatch(host, pattern string) bool {
	pattern = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(pattern), "*."), ".")
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func nilSliceToEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// marshalSorted mimics Python's json.dumps(sort_keys=True) for our flat map.
func marshalSorted(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}
