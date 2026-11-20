package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeBackend records what the gateway forwarded: the path it saw and, for
// /api/approve, the operator in the body.
type seen struct {
	path     string
	operator string
}

func newBackend(rec *seen) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findings":[],"tasks":[]}`))
	})
	mux.HandleFunc("/api/approve", func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec.operator, _ = body["operator"].(string)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"confirmed":"t001"}`))
	})
	return httptest.NewServer(mux)
}

func testGateway(t *testing.T, backendURL string) *gateway {
	t.Helper()
	reg := map[string]string{"ACME": backendURL, "OTHER": backendURL}
	tokens := map[string]principal{
		"good":  {Operator: "esmadi", Engagements: []string{"ACME"}},
		"admin": {Operator: "root", Engagements: []string{"*"}},
	}
	g, err := newGateway(reg, tokens)
	if err != nil {
		t.Fatalf("newGateway: %v", err)
	}
	return g
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestUnauthenticatedRejected(t *testing.T) {
	be := newBackend(&seen{})
	defer be.Close()
	h := testGateway(t, be.URL).routes()
	if w := do(t, h, "GET", "/engagements/ACME/api/graph", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if w := do(t, h, "GET", "/engagements/ACME/api/graph", "bogus", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: want 401, got %d", w.Code)
	}
}

func TestProxyStripsPrefix(t *testing.T) {
	rec := &seen{}
	be := newBackend(rec)
	defer be.Close()
	h := testGateway(t, be.URL).routes()
	w := do(t, h, "GET", "/engagements/ACME/api/graph", "good", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if rec.path != "/api/graph" {
		t.Fatalf("backend saw %q, want /api/graph (prefix not stripped)", rec.path)
	}
}

func TestEngagementAuthorization(t *testing.T) {
	be := newBackend(&seen{})
	defer be.Close()
	h := testGateway(t, be.URL).routes()
	// esmadi may see ACME but not OTHER
	if w := do(t, h, "GET", "/engagements/OTHER/api/graph", "good", ""); w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for out-of-scope engagement, got %d", w.Code)
	}
	// admin ("*") may
	if w := do(t, h, "GET", "/engagements/OTHER/api/graph", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("admin want 200, got %d", w.Code)
	}
	// unknown engagement -> 404
	if w := do(t, h, "GET", "/engagements/NOPE/api/graph", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown engagement, got %d", w.Code)
	}
}

func TestApproveOperatorIsAuthenticatedIdentity(t *testing.T) {
	rec := &seen{}
	be := newBackend(rec)
	defer be.Close()
	h := testGateway(t, be.URL).routes()
	// client tries to spoof operator=attacker; gateway must overwrite with esmadi
	w := do(t, h, "POST", "/engagements/ACME/api/approve", "good",
		`{"task_id":"t001","operator":"attacker"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if rec.path != "/api/approve" {
		t.Fatalf("backend saw %q, want /api/approve", rec.path)
	}
	if rec.operator != "esmadi" {
		t.Fatalf("operator reaching backend = %q, want esmadi (spoof not overwritten)", rec.operator)
	}
}

func TestListEngagements(t *testing.T) {
	be := newBackend(&seen{})
	defer be.Close()
	h := testGateway(t, be.URL).routes()
	w := do(t, h, "GET", "/api/engagements", "good", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var out struct {
		Operator    string   `json:"operator"`
		Engagements []string `json:"engagements"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Operator != "esmadi" || len(out.Engagements) != 1 || out.Engagements[0] != "ACME" {
		t.Fatalf("got %+v, want operator=esmadi engagements=[ACME]", out)
	}
}

func TestConsoleServedAtRoot(t *testing.T) {
	be := newBackend(&seen{})
	defer be.Close()
	g := testGateway(t, be.URL)
	g.console = []byte("<!doctype html><title>RT</title>")
	h := g.routes()
	w := do(t, h, "GET", "/", "", "") // static page needs no auth
	if w.Code != http.StatusOK {
		t.Fatalf("console: want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("console content-type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "RT") {
		t.Fatal("console body not served")
	}
}

func TestHealthz(t *testing.T) {
	be := newBackend(&seen{})
	defer be.Close()
	h := testGateway(t, be.URL).routes()
	if w := do(t, h, "GET", "/healthz", "", ""); w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("healthz: got %d %q", w.Code, w.Body.String())
	}
}
