// Package main is RT's API gateway + approval service — the operator console's
// backend. It exposes the engagement to the operator UI and, critically, holds
// the approval queue for gated (exploit+) tasks: the console lists tasks
// awaiting confirmation and POSTs the operator's approval, which the
// orchestrator then honors (rt confirm).
//
// SCAFFOLD STATUS: endpoints return placeholders. The real implementation
// fronts the orchestrator's engagement graph and writes to the immutable audit
// log on every action.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
)

type approval struct {
	TaskID   string `json:"task_id"`
	Operator string `json:"operator"`
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	mux := http.NewServeMux()

	// Health.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Approval queue (GET) — tasks awaiting operator confirmation.
	mux.HandleFunc("/api/approvals", func(w http.ResponseWriter, r *http.Request) {
		// TODO: read from the orchestrator (awaiting_confirmation()).
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{})
	})

	// Approve a gated task (POST). Every call must be written to the audit log.
	mux.HandleFunc("/api/approve", func(w http.ResponseWriter, r *http.Request) {
		var a approval
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// TODO: invoke `rt confirm <task> --operator <op>` and append to audit log.
		log.Printf("approval received: task=%s operator=%s (scaffold: not applied)", a.TaskID, a.Operator)
		w.WriteHeader(http.StatusAccepted)
	})

	log.Printf("rt-gateway scaffold listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
