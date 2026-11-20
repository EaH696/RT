package main

import (
	"context"
	"errors"
	"testing"
)

// fakeRuntime records the spec it was handed and reports a chosen isolation.
type fakeRuntime struct {
	isolated bool
	got      ContainerSpec
	ran      bool
}

func (f *fakeRuntime) Name() string   { return "fake" }
func (f *fakeRuntime) Isolated() bool  { return f.isolated }
func (f *fakeRuntime) Run(_ context.Context, spec ContainerSpec) (ToolResult, error) {
	f.ran = true
	f.got = spec
	return ToolResult{Stdout: "ok", ExitCode: 0}, nil
}

func TestRunnerPassesEgressProxyAndArgvToRuntime(t *testing.T) {
	rt := &fakeRuntime{isolated: true}
	r := &Runner{Gate: allowGate{true}, Adapters: DefaultAdapters(),
		Runtime: rt, EgressProxy: "127.0.0.1:8900"}
	res, err := r.Run(context.Background(), ToolRequest{
		Tool: "nmap", Target: "10.0.0.5", Tier: TierRecon,
		Args: map[string]string{"profile": "quick"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rt.ran || res.Stdout != "ok" {
		t.Fatal("runtime was not invoked")
	}
	if rt.got.EgressProxy != "127.0.0.1:8900" {
		t.Fatalf("egress proxy not propagated: %q", rt.got.EgressProxy)
	}
	if n := len(rt.got.Argv); n == 0 || rt.got.Argv[n-1] != "10.0.0.5" {
		t.Fatalf("argv not built/propagated: %v", rt.got.Argv)
	}
}

func TestRunnerFailsClosedOnUnisolatedRuntime(t *testing.T) {
	rt := &fakeRuntime{isolated: false}
	r := &Runner{Gate: allowGate{true}, Adapters: DefaultAdapters(), Runtime: rt}
	_, err := r.Run(context.Background(), ToolRequest{Tool: "nmap", Target: "10.0.0.5", Tier: TierRecon})
	if err == nil {
		t.Fatal("must refuse to run on a non-isolated runtime by default (fail closed)")
	}
	if rt.ran {
		t.Fatal("must not have executed the tool")
	}
}

func TestGatedTierNeverRunsUnisolatedEvenWithOverride(t *testing.T) {
	rt := &fakeRuntime{isolated: false}
	r := &Runner{Gate: allowGate{true}, Adapters: DefaultAdapters(),
		Runtime: rt, AllowUnisolated: true} // dev override set...
	_, err := r.Run(context.Background(), ToolRequest{
		Tool: "nmap", Target: "10.0.0.5", Tier: TierExploit, Confirmed: true,
	})
	if err == nil {
		t.Fatal("gated tier must never run on a non-isolated runtime, override or not")
	}
	if rt.ran {
		t.Fatal("gated tool must not have executed unisolated")
	}
}

func TestUnisolatedAllowedForDevWithOverride(t *testing.T) {
	rt := &fakeRuntime{isolated: false}
	r := &Runner{Gate: allowGate{true}, Adapters: DefaultAdapters(),
		Runtime: rt, AllowUnisolated: true}
	if _, err := r.Run(context.Background(), ToolRequest{Tool: "nmap", Target: "10.0.0.5", Tier: TierRecon}); err != nil {
		t.Fatalf("recon tier with dev override should run: %v", err)
	}
	if !rt.ran {
		t.Fatal("expected the tool to run under the dev override")
	}
}

func TestPinnedRuntimeFailsClosedUntilImplemented(t *testing.T) {
	_, err := (PinnedRuntime{Kind: "gvisor"}).Run(context.Background(), ContainerSpec{Argv: []string{"echo"}})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("pinned runtime must fail closed with ErrRuntimeUnavailable, got %v", err)
	}
}

func TestLocalRuntimeRunsAndCaptures(t *testing.T) {
	res, err := (LocalRuntime{}).Run(context.Background(), ContainerSpec{Argv: []string{"echo", "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("local runtime stdout = %q", res.Stdout)
	}
	if (LocalRuntime{}).Isolated() {
		t.Fatal("local runtime must report Isolated()=false")
	}
}
