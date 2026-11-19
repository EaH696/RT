package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
)

// The policy-gate service. The orchestrator POSTs {"target": "..."} to /check
// and gets a Decision. In production this process ALSO runs the egress proxy
// (see proxy.go) so the sandbox can physically reach only in-scope hosts; that
// part is stubbed in this scaffold.
func main() {
	scopePath := flag.String("scope", "scope.json", "path to signed scope.json")
	addr := flag.String("addr", ":8700", "listen address")
	flag.Parse()

	scope, err := loadScope(*scopePath)
	if err != nil {
		log.Fatalf("load scope: %v", err)
	}
	if !scope.Verify() {
		log.Fatalf("REFUSING TO START: scope %s has an invalid or missing signature", *scopePath)
	}
	log.Printf("policy-gate up for engagement %s (scope signed by %v)", scope.EngagementID, deref(scope.SignedBy))

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

func deref(s *string) string {
	if s == nil {
		return "?"
	}
	return *s
}
