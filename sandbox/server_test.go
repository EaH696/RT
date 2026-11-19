package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fake policy-gate: allows only 10.0.0.5.
func fakeGate() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target string `json:"target"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := req.Target == "10.0.0.5"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"target": req.Target, "allowed": allowed, "reason": "test",
		})
	}))
}

func runRequest(t *testing.T, srv *httptest.Server, body map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/run", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestRunDeniesOutOfScope(t *testing.T) {
	gate := fakeGate()
	defer gate.Close()
	runner := &Runner{Gate: newHTTPGate(gate.URL), Adapters: DefaultAdapters()}
	srv := httptest.NewServer(ToolRunnerServer(runner))
	defer srv.Close()

	out := runRequest(t, srv, map[string]any{
		"tool": "nmap", "target": "10.9.9.9", "tier": "recon",
	})
	if errStr, _ := out["err"].(string); !strings.Contains(errStr, "DENIED") {
		t.Fatalf("expected DENIED for out-of-scope target, got err=%q", errStr)
	}
}

func TestRunRefusesUnconfirmedExploit(t *testing.T) {
	gate := fakeGate()
	defer gate.Close()
	runner := &Runner{Gate: newHTTPGate(gate.URL), Adapters: DefaultAdapters()}
	srv := httptest.NewServer(ToolRunnerServer(runner))
	defer srv.Close()

	out := runRequest(t, srv, map[string]any{
		"tool": "nmap", "target": "10.0.0.5", "tier": "exploit", "confirmed": false,
	})
	if errStr, _ := out["err"].(string); !strings.Contains(errStr, "confirmation required") {
		t.Fatalf("expected confirmation-required refusal, got err=%q", errStr)
	}
}

func TestHTTPGateParsesDecision(t *testing.T) {
	gate := fakeGate()
	defer gate.Close()
	g := newHTTPGate(gate.URL)
	ok, _, err := g.Permit(context.Background(), "10.0.0.5")
	if err != nil || !ok {
		t.Fatalf("expected allow for in-scope target, ok=%v err=%v", ok, err)
	}
}
