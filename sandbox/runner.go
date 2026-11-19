// Package main is RT's tool-execution sandbox. Agents never run tools in their
// own process; they ask the sandbox to run a named tool against a target. Each
// run is validated (tier + scope) and then executed through a Runtime that
// pins the tool's egress to the EgressProxy, so a tool can physically reach
// only in-scope hosts.
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
	Tool      string            `json:"tool"`
	Target    string            `json:"target"`
	Args      map[string]string `json:"args"`
	Tier      RiskTier          `json:"tier"`
	Confirmed bool              `json:"confirmed"`
	Timeout   time.Duration     `json:"timeout"`
}

// ToolResult is what the agent gets back.
type ToolResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Err      string `json:"err,omitempty"`
}

// ScopeChecker is satisfied by a client of the policy-gate.
type ScopeChecker interface {
	Permit(ctx context.Context, target string) (bool, string, error)
}

// Adapter normalizes one external tool into argv.
type Adapter interface {
	Name() string
	Argv(req ToolRequest) ([]string, error)
}

// Runner executes tool requests after enforcing tier and scope, through a
// Runtime that confines the tool and pins its egress to EgressProxy.
type Runner struct {
	Gate        ScopeChecker
	Adapters    map[string]Adapter
	Runtime     Runtime // defaults to LocalRuntime when nil (dev)
	EgressProxy string  // URL the tool's only egress route must use
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
	rt := r.Runtime
	if rt == nil {
		rt = LocalRuntime{}
	}
	return rt.Exec(ctx, ContainerSpec{
		Argv:        argv,
		EgressProxy: r.EgressProxy,
		Timeout:     req.Timeout,
	})
}
