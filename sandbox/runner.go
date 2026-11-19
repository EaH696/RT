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
	"os/exec"
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

// Runner executes tool requests after enforcing tier and scope.
type Runner struct {
	Gate     ScopeChecker
	Adapters map[string]Adapter
}

func (r *Runner) Run(ctx context.Context, req ToolRequest) (ToolResult, error) {
	if req.Tier.Gated() && !req.Confirmed {
		return ToolResult{}, fmt.Errorf("refusing %s tool %q: operator confirmation required", req.Tier, req.Tool)
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
	// TODO(appliance): launch argv inside an ephemeral container whose egress
	// is pinned to the policy-gate proxy. This local exec is a scaffold stand-in.
	to := req.Timeout
	if to == 0 {
		to = 120 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	out, _ := cmd.Output()
	res := ToolResult{Stdout: string(out)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	return res, nil
}
