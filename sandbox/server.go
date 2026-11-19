package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// wireRequest is the JSON shape of proto ToolRequest on the HTTP transport.
type wireRequest struct {
	Tool      string            `json:"tool"`
	Target    string            `json:"target"`
	Args      map[string]string `json:"args"`
	Tier      string            `json:"tier"`
	Confirmed bool              `json:"confirmed"`
	Timeout   int               `json:"timeout_seconds"`
}

// httpGate implements ScopeChecker by calling the policy-gate /check endpoint.
// This is the sandbox's own scope re-check — it does not trust that the
// orchestrator already checked.
type httpGate struct {
	baseURL string
	client  *http.Client
}

func newHTTPGate(baseURL string) httpGate {
	return httpGate{baseURL: baseURL, client: &http.Client{Timeout: 10 * time.Second}}
}

func (g httpGate) Permit(ctx context.Context, target string) (bool, string, error) {
	body, _ := json.Marshal(map[string]string{"target": target})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+"/check", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	var d struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return false, "", err
	}
	return d.Allowed, d.Reason, nil
}

// ToolRunnerServer serves ToolRunner.Run over HTTP+JSON (see proto/rt.proto).
func ToolRunnerServer(runner *Runner) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		var wr wireRequest
		if err := json.NewDecoder(r.Body).Decode(&wr); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req := ToolRequest{
			Tool: wr.Tool, Target: wr.Target, Args: wr.Args,
			Tier: RiskTier(wr.Tier), Confirmed: wr.Confirmed,
			Timeout: time.Duration(wr.Timeout) * time.Second,
		}
		res, err := runner.Run(r.Context(), req)
		if err != nil {
			res.Err = err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"exit_code": res.ExitCode, "stdout": res.Stdout,
			"stderr": res.Stderr, "err": res.Err,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	return mux
}
