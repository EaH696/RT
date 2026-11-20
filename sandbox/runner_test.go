package main

import (
	"context"
	"testing"
)

type allowGate struct{ allow bool }

func (g allowGate) Permit(_ context.Context, _ string) (bool, string, error) {
	return g.allow, "test", nil
}

func TestAdapterArgvTargetLast(t *testing.T) {
	argv, err := nmapAdapter{}.Argv(ToolRequest{Target: "10.0.0.5", Args: map[string]string{"profile": "quick"}})
	if err != nil {
		t.Fatal(err)
	}
	if argv[len(argv)-1] != "10.0.0.5" {
		t.Fatalf("target must be the final argv element, got %v", argv)
	}
}

func TestGatedToolNeedsConfirmation(t *testing.T) {
	r := &Runner{Gate: allowGate{true}, Adapters: DefaultAdapters()}
	_, err := r.Run(context.Background(), ToolRequest{
		Tool: "nmap", Target: "10.0.0.5", Tier: TierExploit, Confirmed: false,
	})
	if err == nil {
		t.Fatal("exploit-tier tool must be refused without confirmation")
	}
}

func TestOutOfScopeToolDenied(t *testing.T) {
	r := &Runner{Gate: allowGate{false}, Adapters: DefaultAdapters(), AllowUnisolated: true}
	_, err := r.Run(context.Background(), ToolRequest{
		Tool: "nmap", Target: "10.9.9.9", Tier: TierRecon,
	})
	if err == nil {
		t.Fatal("tool against out-of-scope target must be denied by the gate")
	}
}

func TestPortSanitize(t *testing.T) {
	// Only [0-9,-] survive (dash kept for ranges like 80-443); letters,
	// spaces, ';' and '/' are stripped, so args can't smuggle a shell command.
	if got := sanitizePorts("22,80; rm -rf /"); got != "22,80-" {
		t.Fatalf("sanitizePorts leaked characters: %q", got)
	}
}
