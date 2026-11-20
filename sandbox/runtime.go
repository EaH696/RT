package main

// ContainerRuntime is the seam between RT's tool runner and the host isolation
// mechanism. Every tool runs through a runtime whose job is to execute argv
// with its network egress PINNED to a single proxy — the policy-gate's egress
// proxy — so a tool can physically reach only in-scope hosts, and nothing else.
//
// This is the "physical" half of RT's defense in depth. The "logical" half (the
// policy-gate decision) already runs before we get here; a correct runtime makes
// the guarantee hold even against a confused or compromised tool that ignores
// proxy settings and opens raw sockets, because the pin is enforced in the
// kernel (netns + nftables), not by asking the tool nicely.
//
// Implementations MUST fail CLOSED: if egress cannot be pinned to the proxy,
// the tool must not run at all. A runtime that cannot guarantee the pin returns
// an error instead of executing with open egress.
//
// Two implementations are intended:
//   - LocalRuntime: NO isolation. Runs argv in-process-host with the proxy only
//     advertised via env. Dev/CI only — documented as unsafe for engagements.
//   - A gVisor/Firecracker runtime (PinnedRuntime, below): the appliance
//     backend. Not yet implemented here — see docs/EGRESS.md — because it needs
//     a host with the runtime installed to build and test against.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// ContainerSpec is one tool execution request for a runtime: the command to run
// and the egress constraint it must be run under.
type ContainerSpec struct {
	Argv        []string          // the tool command line (from the adapter)
	Timeout     time.Duration     // hard wall-clock cap
	EgressProxy string            // host:port that must be the tool's ONLY network route
	Image       string            // optional container image for the tool
	Env         map[string]string // extra environment for the tool
}

// ContainerRuntime executes a ContainerSpec under its isolation guarantee.
type ContainerRuntime interface {
	// Name identifies the runtime (for logs and operator visibility).
	Name() string
	// Run executes spec.Argv with egress pinned to spec.EgressProxy. It MUST
	// fail closed: if the pin cannot be guaranteed, return an error and do not
	// execute.
	Run(ctx context.Context, spec ContainerSpec) (ToolResult, error)
	// Isolated reports whether this runtime physically enforces the egress pin.
	// The runner refuses to run gated (exploit+) tiers on a non-isolated runtime.
	Isolated() bool
}

// ErrRuntimeUnavailable is returned by a runtime that cannot guarantee its
// isolation on this host (missing binary, no privilege). Fail closed.
var ErrRuntimeUnavailable = fmt.Errorf("container runtime unavailable on this host")

// --------------------------------------------------------------------------- //
// LocalRuntime — dev/CI only, NOT isolated
// --------------------------------------------------------------------------- //

// LocalRuntime runs the tool directly on the host with no network isolation. It
// advertises the egress proxy via HTTP(S)_PROXY so proxy-aware tools route
// through it, but it CANNOT stop a tool from opening a direct socket. It is for
// development and CI only; Isolated() reports false, so the runner will refuse
// gated tiers on it.
type LocalRuntime struct{}

func (LocalRuntime) Name() string   { return "local" }
func (LocalRuntime) Isolated() bool { return false }

func (LocalRuntime) Run(ctx context.Context, spec ContainerSpec) (ToolResult, error) {
	if len(spec.Argv) == 0 {
		return ToolResult{}, fmt.Errorf("empty argv")
	}
	to := spec.Timeout
	if to == 0 {
		to = 120 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	cmd := exec.CommandContext(cctx, spec.Argv[0], spec.Argv[1:]...)
	cmd.Env = os.Environ()
	if spec.EgressProxy != "" {
		// Best-effort: proxy-aware tools will route through the gate. This is
		// NOT a security boundary (raw sockets escape it) — see Isolated().
		proxy := "http://" + spec.EgressProxy
		cmd.Env = append(cmd.Env, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy,
			"http_proxy="+proxy, "https_proxy="+proxy)
	}
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdout, err := cmd.Output()
	res := ToolResult{Stdout: string(stdout)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		res.Stderr = string(ee.Stderr)
	} else if err != nil {
		res.Err = err.Error()
	}
	return res, nil
}

// --------------------------------------------------------------------------- //
// PinnedRuntime — the appliance backend (gVisor/Firecracker). NOT YET BUILT.
// --------------------------------------------------------------------------- //

// PinnedRuntime is the placeholder for the real isolated runtime. The design —
// an ephemeral gVisor (runsc) or Firecracker guest in a network namespace whose
// nftables ruleset DROPs all egress except a transparent redirect to the
// policy-gate proxy — is specified in docs/EGRESS.md. It is not implemented in
// this repo yet because it must be built and tested against a host that has the
// runtime installed; shipping an untested isolation path would be worse than an
// honest placeholder.
//
// It is wired as a real ContainerRuntime so the runner and tests already treat
// it as the isolated backend; Run fails CLOSED until the host-side work lands.
type PinnedRuntime struct {
	Kind string // "gvisor" | "firecracker"
}

func (p PinnedRuntime) Name() string   { return "pinned:" + p.Kind }
func (p PinnedRuntime) Isolated() bool { return true }

func (p PinnedRuntime) Run(ctx context.Context, spec ContainerSpec) (ToolResult, error) {
	return ToolResult{}, fmt.Errorf("%w: %s runtime not yet implemented (see docs/EGRESS.md); "+
		"refusing to run with unpinned egress", ErrRuntimeUnavailable, p.Kind)
}
