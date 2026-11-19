package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Runtime launches one tool invocation. The whole point of RT's sandbox is that
// a tool runs isolated and with its egress pinned to the EgressProxy, so its
// only possible network destinations are in-scope hosts.
//
// Two implementations:
//   - LocalRuntime     — dev: a subprocess with proxy env set. NO isolation.
//   - ContainerRuntime  — prod: an ephemeral gVisor/Firecracker container whose
//                         only route is the proxy. Stubbed here (needs a host
//                         with the runtime installed).
type Runtime interface {
	Exec(ctx context.Context, spec ContainerSpec) (ToolResult, error)
}

type ContainerSpec struct {
	Argv        []string
	EgressProxy string // e.g. http://127.0.0.1:8720 — the ONLY egress route
	Timeout     time.Duration
	Image       string // used by ContainerRuntime
}

// LocalRuntime runs the tool as a child process. It sets HTTP(S)_PROXY so
// proxy-aware tools route through the egress proxy, and enforces a timeout.
//
// WARNING: this provides NO isolation and does NOT physically confine
// raw-socket tools to the proxy — it is for development only. Production uses
// ContainerRuntime. The scope guarantee for LocalRuntime rests on the
// dispatch-time gate check and the proxy for proxy-aware traffic, not on
// containment.
type LocalRuntime struct{}

func (LocalRuntime) Exec(ctx context.Context, spec ContainerSpec) (ToolResult, error) {
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
	if spec.EgressProxy != "" {
		cmd.Env = append(cmd.Environ(),
			"HTTP_PROXY="+spec.EgressProxy, "HTTPS_PROXY="+spec.EgressProxy,
			"http_proxy="+spec.EgressProxy, "https_proxy="+spec.EgressProxy,
			// defense in depth: no implicit no_proxy bypass
			"NO_PROXY=", "no_proxy=",
		)
	}
	out, err := cmd.Output()
	res := ToolResult{Stdout: string(out)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	// A timeout kills the process, which surfaces as an ExitError (signal:
	// killed) — so check the deadline FIRST, before treating err as a normal
	// non-zero exit.
	if cctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("tool timed out after %s", to)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		res.Stderr = string(ee.Stderr)
	}
	return res, nil
}

// ContainerRuntime is the production runtime: each run is an ephemeral container
// (gVisor runsc / Firecracker) with no default route — its ONLY egress is the
// EgressProxy, enforced by the container network config (nftables/transparent
// redirect), so even raw-socket tools cannot reach an out-of-scope host.
//
// Stubbed: wiring this needs a host with the container runtime installed, which
// this scaffold's environment does not provide. The interface and the egress
// contract are the parts fixed now.
type ContainerRuntime struct {
	RunShim string // path to the launcher (e.g. runsc / firecracker wrapper)
}

func (c ContainerRuntime) Exec(_ context.Context, _ ContainerSpec) (ToolResult, error) {
	return ToolResult{}, fmt.Errorf(
		"ContainerRuntime not available on this host: install a container runtime " +
			"(gVisor/Firecracker) and set RunShim; the container must route egress " +
			"only through spec.EgressProxy")
}
