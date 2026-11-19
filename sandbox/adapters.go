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

// DefaultAdapters is the registry the sandbox boots with.
func DefaultAdapters() map[string]Adapter {
	m := map[string]Adapter{}
	for _, a := range []Adapter{nmapAdapter{}, nucleiAdapter{}} {
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
