package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
)

// The policy-gate service. The orchestrator POSTs {"target": "..."} to /check
// and gets a Decision. In production this process ALSO runs the egress proxy
// (see proxy.go) so the sandbox can physically reach only in-scope hosts; that
// part is stubbed in this scaffold.
func main() {
	scopePath := flag.String("scope", "scope.json", "path to signed scope.json")
	trustPath := flag.String("trust", "trust.json", "trusted operator public keys (JSON array of hex)")
	addr := flag.String("addr", ":8700", "listen address")
	flag.Parse()

	trust, err := loadTrust(*trustPath)
	if err != nil {
		log.Fatalf("load trust store: %v", err)
	}
	if len(trust) == 0 {
		log.Fatalf("REFUSING TO START: trust store %s has no operator public keys", *trustPath)
	}
	scope, err := loadScope(*scopePath)
	if err != nil {
		log.Fatalf("load scope: %v", err)
	}
	scope = scope.WithTrust(trust)
	if !scope.VerifyTrusted(trust) {
		log.Fatalf("REFUSING TO START: scope %s has an invalid signature or an untrusted signing key", *scopePath)
	}
	log.Printf("policy-gate up for engagement %s (scope signed by %v, key trusted)", scope.EngagementID, deref(scope.SignedBy))

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		d := scope.Decide(req.Target)
		if !d.Allowed {
			log.Printf("DENY %s: %s", d.Target, d.Reason)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	})

	log.Fatal(http.ListenAndServe(*addr, nil))
}

func loadScope(path string) (Scope, error) {
	var s Scope
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// loadTrust reads the provisioned operator public keys (hex) into a set.
func loadTrust(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []string
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, err
	}
	trust := make(map[string]bool, len(keys))
	for _, k := range keys {
		if k = trimKey(k); k != "" {
			trust[k] = true
		}
	}
	return trust, nil
}

func trimKey(k string) string {
	return strings.TrimSpace(k)
}

func deref(s *string) string {
	if s == nil {
		return "?"
	}
	return *s
}
