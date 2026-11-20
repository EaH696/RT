// Package main is RT's tool-execution sandbox. Agents never run tools in their
// own process; they ask the sandbox to run a named tool against a target. Each
// run happens in an ephemeral, egress-controlled container (gVisor/Firecracker
// recommended on the appliance) whose ONLY network route is through the
// policy-gate's egress proxy — so a tool can physically reach only in-scope
// hosts.
//
// SCAFFOLD STATUS: the container lifecycle is stubbed (it runs the tool
// locally with a timeout and captures output). Wire Run() to your container
// runtime before production. The Tool contract and the pre-flight scope check
// are the parts worth getting right now.
package main

import (
	"context"
	"fmt"
	"time"
)

// RiskTier mirrors the orchestrator's tiers; the sandbox refuses to run an
// exploit+ tool unless the request is marked confirmed.
type RiskTier string

const (
	TierRecon       RiskTier = "recon"
	TierEnum        RiskTier = "enum"
	TierAnalysis    RiskTier = "analysis"
	TierExploit     RiskTier = "exploit"
	TierPost        RiskTier = "post"
	TierDestructive RiskTier = "destructive"
)

func (t RiskTier) Gated() bool {
	return t == TierExploit || t == TierPost || t == TierDestructive
}

// ToolRequest is one tool invocation an agent asked for.
type ToolRequest struct {
	Tool      string            `json:"tool"`       // e.g. "nmap", "nuclei"
	Target    string            `json:"target"`     // the asset to act on
	Args      map[string]string `json:"args"`       // normalized, per-adapter
	Tier      RiskTier          `json:"tier"`
	Confirmed bool              `json:"confirmed"`  // operator approval carried from the task
	Timeout   time.Duration     `json:"timeout"`
}

// ToolResult is what the agent gets back.
type ToolResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Err      string `json:"err,omitempty"`
}

// ScopeChecker is satisfied by a client of the policy-gate. The sandbox calls
// it before every run — belt to the egress proxy's braces.
type ScopeChecker interface {
	Permit(ctx context.Context, target string) (bool, string, error)
}

// Adapter normalizes one external tool into argv. Keeping this an interface is
// what lets RT grow a library of tools without touching the runner.
type Adapter interface {
	Name() string
	// Argv builds the command line for a target + normalized args.
	Argv(req ToolRequest) ([]string, error)
}

// Runner executes tool requests after enforcing tier and scope, then hands the
// command to a ContainerRuntime that pins egress to the policy-gate proxy.
type Runner struct {
	Gate     ScopeChecker
	Adapters map[string]Adapter
	Runtime  ContainerRuntime // defaults to LocalRuntime (dev/CI, NOT isolated)
	// EgressProxy is the host:port every tool's network traffic must be pinned
	// to. Passed to the runtime in each ContainerSpec.
	EgressProxy string
	// AllowUnisolated permits running on a non-isolated runtime (LocalRuntime).
	// Defaults false: the sandbox refuses to run unless egress can be pinned —
	// fail closed. Set true only for development.
	AllowUnisolated bool
}

func (r *Runner) runtime() ContainerRuntime {
	if r.Runtime != nil {
		return r.Runtime
	}
	return LocalRuntime{}
}

func (r *Runner) Run(ctx context.Context, req ToolRequest) (ToolResult, error) {
	if req.Tier.Gated() && !req.Confirmed {
		return ToolResult{}, fmt.Errorf("refusing %s tool %q: operator confirmation required", req.Tier, req.Tool)
	}
	rt := r.runtime()
	// Fail closed: without physical egress isolation we cannot guarantee a tool
	// stays in scope, so by default we refuse to run at all. Gated (exploit+)
	// tiers may NEVER run unisolated, regardless of the dev override.
	if !rt.Isolated() {
		if req.Tier.Gated() {
			return ToolResult{}, fmt.Errorf("refusing %s tool %q on non-isolated runtime %q: "+
				"gated tiers require pinned egress", req.Tier, req.Tool, rt.Name())
		}
		if !r.AllowUnisolated {
			return ToolResult{}, fmt.Errorf("refusing to run on non-isolated runtime %q "+
				"(egress cannot be pinned); set AllowUnisolated for development", rt.Name())
		}
	}
	if r.Gate != nil {
		ok, reason, err := r.Gate.Permit(ctx, req.Target)
		if err != nil {
			return ToolResult{}, fmt.Errorf("policy-gate check failed: %w", err)
		}
		if !ok {
			return ToolResult{}, fmt.Errorf("DENIED by policy-gate: %s", reason)
		}
	}
	adapter, ok := r.Adapters[req.Tool]
	if !ok {
		return ToolResult{}, fmt.Errorf("no adapter registered for tool %q", req.Tool)
	}
	argv, err := adapter.Argv(req)
	if err != nil {
		return ToolResult{}, err
	}
	return rt.Run(ctx, ContainerSpec{
		Argv:        argv,
		Timeout:     req.Timeout,
		EgressProxy: r.EgressProxy,
	})
}
