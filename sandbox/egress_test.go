package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// gateDouble allows a fixed set of hosts; optionally errors (to test fail-closed).
type gateDouble struct {
	allow map[string]bool
	err   error
}

func (g gateDouble) Permit(_ context.Context, target string) (bool, string, error) {
	if g.err != nil {
		return false, "", g.err
	}
	if g.allow[target] {
		return true, "ok", nil
	}
	return false, fmt.Sprintf("%q out of scope", target), nil
}

func proxyClient(p *EgressProxy) (*http.Client, *httptest.Server) {
	ps := httptest.NewServer(p)
	pu, _ := url.Parse(ps.URL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}, ps
}

func TestEgressAllowsInScopeHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello from target")
	}))
	defer target.Close()
	host := hostOnly(target.Listener.Addr().String()) // 127.0.0.1

	p := NewEgressProxy(gateDouble{allow: map[string]bool{host: true}}, "")
	client, ps := proxyClient(p)
	defer ps.Close()

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from target" {
		t.Fatalf("in-scope request should reach target, got %q", body)
	}
}

func TestEgressBlocksOutOfScopeHTTP(t *testing.T) {
	p := NewEgressProxy(gateDouble{allow: map[string]bool{"10.0.0.5": true}}, "")
	client, ps := proxyClient(p)
	defer ps.Close()

	// host "blocked.example" is not in the allow set -> proxy returns 403, no dial
	resp, err := client.Get("http://blocked.example/")
	if err != nil {
		t.Fatalf("expected a 403 response, not a transport error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope egress must be 403, got %d", resp.StatusCode)
	}
}

func TestEgressBlocksOutOfScopeConnect(t *testing.T) {
	p := NewEgressProxy(gateDouble{allow: map[string]bool{"10.0.0.5": true}}, "")
	client, ps := proxyClient(p)
	defer ps.Close()

	// https -> CONNECT to a denied host; the proxy refuses, so Do returns an error
	_, err := client.Get("https://blocked.example/")
	if err == nil {
		t.Fatal("out-of-scope CONNECT must fail")
	}
}

func TestEgressFailsClosedOnGateError(t *testing.T) {
	p := NewEgressProxy(gateDouble{err: fmt.Errorf("gate down")}, "")
	ok, reason := p.allowed(context.Background(), "10.0.0.5")
	if ok {
		t.Fatal("must deny when the policy-gate is unreachable (fail closed)")
	}
	if reason == "" {
		t.Fatal("expected a reason on fail-closed denial")
	}
}
