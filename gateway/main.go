// Package main is RT's API gateway — the production edge in front of one or
// more single-appliance `rt serve` console backends. It adds the three things
// `rt serve` deliberately does not: authentication, TLS, and multi-engagement
// routing. The orchestrator and its console stay dependency-free and bind
// loopback; this gateway is what an operator's browser actually talks to.
//
// Responsibilities:
//
//   - AuthN/AuthZ. Every /api and /engagements request carries a bearer token.
//     The token resolves to an operator identity and the set of engagements
//     that operator may see. Unknown token -> 401; out-of-scope engagement ->
//     403.
//   - Routing. /engagements/{id}/api/... is reverse-proxied to that
//     engagement's backend (from the registry), with the /engagements/{id}
//     prefix stripped so the backend sees its normal /api/... path.
//   - Approval integrity. On POST .../api/approve the gateway OVERWRITES the
//     `operator` field with the authenticated identity before forwarding, so
//     the audit trail records who actually approved — never a client-supplied
//     name. This is the point of putting auth in front of the console.
//
// Config is two JSON files (see deploy/gateway/*.example.json):
//
//	registry.json : { "<engagement_id>": "http://127.0.0.1:8070", ... }
//	tokens.json   : [ { "token": "...", "operator": "esmadi",
//	                    "engagements": ["ACME-2026"] }, ... ]   // ["*"] = all
//
// TLS is enabled when -tls-cert and -tls-key are given; otherwise the gateway
// serves plain HTTP and logs a loud warning (fine for loopback dev, never for
// a real engagement).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

// ---- config -------------------------------------------------------------- //

type principal struct {
	Operator    string   `json:"operator"`
	Engagements []string `json:"engagements"`
}

func (p principal) canSee(id string) bool {
	for _, e := range p.Engagements {
		if e == "*" || e == id {
			return true
		}
	}
	return false
}

type gateway struct {
	registry map[string]string            // engagement id -> backend base URL
	proxies  map[string]*httputil.ReverseProxy
	tokens   map[string]principal         // bearer token -> principal
}

func loadRegistry(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func loadTokens(path string) (map[string]principal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []struct {
		Token string `json:"token"`
		principal
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	out := make(map[string]principal, len(list))
	for _, t := range list {
		if t.Token == "" || t.Operator == "" {
			continue // a token with no identity is useless; skip it
		}
		out[t.Token] = t.principal
	}
	return out, nil
}

func newGateway(registry map[string]string, tokens map[string]principal) (*gateway, error) {
	proxies := make(map[string]*httputil.ReverseProxy, len(registry))
	for id, backend := range registry {
		u, err := url.Parse(backend)
		if err != nil {
			return nil, err
		}
		target := u
		rp := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(target)                 // scheme+host of the backend
				r.Out.Host = target.Host
				r.SetXForwarded()
			},
		}
		proxies[id] = rp
	}
	return &gateway{registry: registry, proxies: proxies, tokens: tokens}, nil
}

// ---- auth ---------------------------------------------------------------- //

func (g *gateway) authenticate(r *http.Request) (principal, bool) {
	h := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(h, pfx) {
		return principal{}, false
	}
	p, ok := g.tokens[strings.TrimSpace(h[len(pfx):])]
	return p, ok
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- handlers ------------------------------------------------------------ //

// listEngagements returns the engagement ids this principal may see.
func (g *gateway) listEngagements(w http.ResponseWriter, r *http.Request) {
	p, ok := g.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	ids := make([]string, 0, len(g.registry))
	for id := range g.registry {
		if p.canSee(id) {
			ids = append(ids, id)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"operator": p.Operator, "engagements": ids})
}

// proxy routes /engagements/{id}/api/... to the backend, after auth + authz,
// and injects the authenticated operator on approvals.
func (g *gateway) proxy(w http.ResponseWriter, r *http.Request) {
	p, ok := g.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id := r.PathValue("id")
	rp, known := g.proxies[id]
	if !known {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown engagement"})
		return
	}
	if !p.canSee(id) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	// Strip the /engagements/{id} prefix so the backend sees its own /api/...
	rest := strings.TrimPrefix(r.URL.Path, "/engagements/"+id)
	if rest == "" {
		rest = "/"
	}
	r.URL.Path = rest

	// Approval integrity: the operator that reaches the audit log is the
	// authenticated identity, never whatever the client put in the body.
	if r.Method == http.MethodPost && rest == "/api/approve" {
		if err := injectOperator(r, p.Operator); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		log.Printf("approval: engagement=%s operator=%s task=%s", id, p.Operator, r.Header.Get("X-RT-Task"))
	}

	rp.ServeHTTP(w, r)
}

// injectOperator rewrites the request body's `operator` field to op and fixes
// Content-Length so the proxied request is well-formed.
func injectOperator(r *http.Request, op string) error {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	body := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
	}
	body["operator"] = op
	if tid, ok := body["task_id"].(string); ok {
		r.Header.Set("X-RT-Task", tid) // for the access log line above
	}
	out, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	r.Header.Set("Content-Type", "application/json")
	return nil
}

func (g *gateway) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /api/engagements", g.listEngagements)
	mux.HandleFunc("/engagements/{id}/", g.proxy)
	return mux
}

// ---- main ---------------------------------------------------------------- //

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	registryPath := flag.String("registry", "registry.json", "engagement->backend registry JSON")
	tokensPath := flag.String("tokens", "tokens.json", "bearer token -> operator JSON")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	flag.Parse()

	registry, err := loadRegistry(*registryPath)
	if err != nil {
		log.Fatalf("registry: %v", err)
	}
	tokens, err := loadTokens(*tokensPath)
	if err != nil {
		log.Fatalf("tokens: %v", err)
	}
	if len(tokens) == 0 {
		log.Fatal("no usable tokens loaded — refusing to start an unauthenticated gateway")
	}
	g, err := newGateway(registry, tokens)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}

	srv := &http.Server{Addr: *addr, Handler: g.routes()}
	log.Printf("rt-gateway: %d engagement(s), %d token(s), listening on %s",
		len(registry), len(tokens), *addr)
	if *tlsCert != "" && *tlsKey != "" {
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Printf("WARNING: serving plain HTTP (no -tls-cert/-tls-key). Use TLS for any real engagement.")
	log.Fatal(srv.ListenAndServe())
}
