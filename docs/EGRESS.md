# Egress enforcement — making scope physical

RT's safety claim is that *a confused or compromised tool cannot reach an asset
outside the signed scope*. Today that is enforced **logically**: the orchestrator
and the Go policy-gate both decide whether a target is in scope before dispatch
(and the gate also enforces the time window and `max_rps`). But a logical check
only stops a tool that *asks*. A tool that ignores its proxy settings and opens a
raw socket to an excluded host is not stopped by a decision — it is stopped only
by the kernel. That kernel-level stop is **egress enforcement**, and it is the
one headline gap remaining.

This document specifies the design. The code seam for it already exists
(`sandbox/runtime.go`): the real runtime is a drop-in behind `ContainerRuntime`.

## The seam (already in the tree)

`Runner.Run` no longer execs tools directly. It builds a `ContainerSpec` and
hands it to a `ContainerRuntime`:

```go
type ContainerSpec struct {
    Argv        []string      // the tool command line (target from the authorized field only)
    Timeout     time.Duration
    EgressProxy string        // host:port that must be the tool's ONLY network route
    Image       string
    Env         map[string]string
}

type ContainerRuntime interface {
    Name() string
    Run(ctx, spec) (ToolResult, error) // MUST fail closed if egress can't be pinned
    Isolated() bool                    // false => runner refuses gated tiers & (by default) all runs
}
```

Two runtimes exist:

- **`LocalRuntime`** — dev/CI only. No isolation; advertises the proxy via
  `HTTP(S)_PROXY` but cannot stop a raw socket. `Isolated()` is `false`, so the
  runner **fails closed**: it refuses to run at all unless `AllowUnisolated` is
  set, and it refuses gated (exploit+) tiers *even then*.
- **`PinnedRuntime`** — the appliance backend described below. Wired as a real
  `ContainerRuntime` with `Isolated() == true`, but its `Run` returns
  `ErrRuntimeUnavailable` until the host-side work lands. Shipping an untested
  isolation path would be worse than an honest fail-closed placeholder.

## The physical model

Each tool run gets an **ephemeral guest** with its **own network namespace**.
Inside that netns the only reachable destination is the policy-gate's egress
proxy; everything else is dropped in the kernel.

```
   tool process (gVisor runsc / Firecracker guest)
        │  all TCP
        ▼
   netns nftables ruleset:
        • default policy DROP (all output)
        • REDIRECT/DNAT all TCP → policy-gate egress proxy (transparent)
        • DROP udp/icmp/raw  (no DNS leak, no ICMP side channel)
        ▼
   policy-gate egress proxy  ── /check(target) ──►  signed scope
        • allow ⇒ connect to the real host
        • deny / gate unreachable ⇒ refuse  (FAIL CLOSED)
```

Properties that make the guarantee hold:

1. **Default-drop.** The netns egress policy is DROP. Nothing leaves except what
   a rule explicitly redirects to the proxy. A raw socket to an excluded IP hits
   the drop.
2. **Transparent redirect.** All TCP is DNAT/REDIRECT'd to the proxy, so a tool
   that ignores `HTTP(S)_PROXY` is still funnelled through it. The proxy asks the
   gate per connection and refuses out-of-scope destinations.
3. **No DNS/ICMP escape.** DNS goes through the proxy (or a pinned in-scope
   resolver); ICMP/raw are dropped, closing side channels.
4. **Fail closed.** If the proxy or gate is unreachable, the connection is
   denied — never defaulted open. The runtime refuses to start the guest at all
   if it cannot install the ruleset.
5. **Ephemeral.** The guest and its netns are torn down after the run; no state
   bleeds between tool runs or engagements.

## Why gVisor / Firecracker

Pentest tools are hostile workloads by nature. A shared-kernel container is a
thin boundary for code that is *designed* to probe and exploit. gVisor (`runsc`)
interposes a user-space kernel; Firecracker gives a real VM boundary. Either is
an acceptable guest; the egress pin (netns + nftables) is the same. Start with
gVisor for density, offer Firecracker where a client requires a VM boundary.

## Build order

1. **`PinnedRuntime.Run` (gVisor).** Launch `spec.Argv` in a `runsc` guest on a
   per-run netns; install the nftables default-drop + transparent-redirect
   ruleset pointing at `spec.EgressProxy`; tear down on exit. Fail closed if the
   ruleset or guest cannot be created. Needs a host with `runsc` + `nftables`.
2. **Policy-gate egress proxy.** The transparent proxy the redirect targets:
   terminate the connection, call the existing `/check`, connect on allow, refuse
   on deny/unreachable. (The gate already has the scope decision; this adds the
   data-plane.)
3. **Integration test on a runtime host.** A tool that tries to reach an excluded
   IP by raw socket must fail; an in-scope target must succeed; killing the gate
   mid-run must fail closed.
4. **Firecracker variant** of step 1 behind the same interface.

## Status

Seam, local runtime, fail-closed runner, and this design: done and tested
(`sandbox/`). Steps 1–4 need a runtime host and are the next milestone — until
they land, run RT only against lab targets you are prepared to reach without the
physical pin, and rely on the logical gate.
