package main

import (
	"fmt"
	"strings"
)

// Example adapters. Each tool RT can drive is one small Adapter: it declares a
// name and turns a normalized ToolRequest into argv. The target always comes
// from req.Target (which the policy-gate has already authorized) — an adapter
// must NEVER accept a target from free-form args, or scope enforcement could be
// bypassed.

type nmapAdapter struct{}

func (nmapAdapter) Name() string { return "nmap" }

func (nmapAdapter) Argv(req ToolRequest) ([]string, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("nmap: empty target")
	}
	argv := []string{"nmap"}
	switch req.Args["profile"] {
	case "", "default":
		argv = append(argv, "-sV", "-T4")
	case "quick":
		argv = append(argv, "-F", "-T4")
	case "full":
		argv = append(argv, "-sV", "-p-", "-T4")
	default:
		return nil, fmt.Errorf("nmap: unknown profile %q", req.Args["profile"])
	}
	if ports := req.Args["ports"]; ports != "" {
		argv = append(argv, "-p", sanitizePorts(ports))
	}
	argv = append(argv, req.Target) // target last, from the authorized field only
	return argv, nil
}

type nucleiAdapter struct{}

func (nucleiAdapter) Name() string { return "nuclei" }

func (nucleiAdapter) Argv(req ToolRequest) ([]string, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("nuclei: empty target")
	}
	argv := []string{"nuclei", "-u", req.Target, "-jsonl"}
	if sev := req.Args["severity"]; sev != "" {
		argv = append(argv, "-severity", sev)
	}
	return argv, nil
}

// httpGetAdapter is a simple HTTP probe (curl). It honors HTTP(S)_PROXY, so in
// the sandbox it routes through the egress proxy — i.e. its requests are
// physically scope-enforced. Useful for recon (banner/headers) and for pulling
// a specific path (e.g. an exposed file) on a confirmed exploit task.
type httpGetAdapter struct{}

func (httpGetAdapter) Name() string { return "httpget" }

func (httpGetAdapter) Argv(req ToolRequest) ([]string, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("httpget: empty target")
	}
	url := req.Target
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	if p := req.Args["path"]; p != "" {
		url = strings.TrimRight(url, "/") + "/" + strings.TrimLeft(p, "/")
	}
	// -sS quiet but show errors, -i include response headers, capped time, and
	// no redirect-following so a redirect can't bounce the tool off-target.
	return []string{"curl", "-sS", "-i", "--max-time", "10", url}, nil
}

// DefaultAdapters is the registry the sandbox boots with.
func DefaultAdapters() map[string]Adapter {
	m := map[string]Adapter{}
	for _, a := range []Adapter{nmapAdapter{}, nucleiAdapter{}, httpGetAdapter{}} {
		m[a.Name()] = a
	}
	return m
}

func sanitizePorts(p string) string {
	ok := func(r rune) bool {
		return (r >= '0' && r <= '9') || r == ',' || r == '-'
	}
	return strings.Map(func(r rune) rune {
		if ok(r) {
			return r
		}
		return -1
	}, p)
}
