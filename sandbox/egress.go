package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// EgressProxy is the sandbox's network enforcement point — the PHYSICAL half of
// scope enforcement. A tool's container is configured so its only route to the
// network is this proxy; the proxy asks the policy-gate whether each
// destination is in scope and refuses the connection if not. So even a tool (or
// a compromised agent) that ignores every logical check still cannot open a
// connection to an out-of-scope host.
//
// It speaks the standard forward-proxy protocol: HTTPS via CONNECT, and plain
// HTTP by forwarding the request. Point a tool at it with HTTP_PROXY/HTTPS_PROXY
// (LocalRuntime does this). Raw-socket tools that ignore proxy env (e.g. nmap
// SYN scans) are handled at the container layer in production by making this
// proxy the container's only permitted egress via nftables/transparent redirect
// — see runtime.go. The scope decision always lives here + the policy-gate.
type EgressProxy struct {
	Gate   ScopeChecker // authoritative scope decision (the policy-gate)
	Engag  string
	Dialer *net.Dialer
}

func NewEgressProxy(gate ScopeChecker, engagement string) *EgressProxy {
	return &EgressProxy{Gate: gate, Engag: engagement, Dialer: &net.Dialer{Timeout: 10 * time.Second}}
}

// allowed asks the policy-gate about a host. Fails CLOSED: any gate error denies.
func (p *EgressProxy) allowed(ctx context.Context, host string) (bool, string) {
	ok, reason, err := p.Gate.Permit(ctx, host)
	if err != nil {
		return false, fmt.Sprintf("policy-gate unreachable, denying: %v", err)
	}
	return ok, reason
}

func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if ok, reason := p.allowed(r.Context(), host); !ok {
		log.Printf("egress DENY CONNECT %s: %s", host, reason)
		http.Error(w, "egress denied: "+reason, http.StatusForbidden)
		return
	}
	upstream, err := p.Dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		upstream.Close()
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(upstream, client)
	go pipe(client, upstream)
}

func (p *EgressProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		host = hostOnly(r.Host)
	}
	if ok, reason := p.allowed(r.Context(), host); !ok {
		log.Printf("egress DENY %s %s: %s", r.Method, host, reason)
		http.Error(w, "egress denied: "+reason, http.StatusForbidden)
		return
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.TrimSuffix(hostport, ".")
}

func pipe(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if strings.EqualFold(k, "Proxy-Connection") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
