# RT Architecture

RT is a self-hosted, semi-autonomous, operator-gated agentic pentest platform.
This document describes the layers, the data model, and how the design was
adapted from sapper-v2.

## Layers

```
            ┌──────────────┐
            │  Commander    │  (planner; templates/command.md)
            └──────┬───────┘
     phase/tier ───┤   creates Tasks along the kill chain
   ┌───────────────┼────────────────┐
   ▼               ▼                ▼
 Recon agent   Exploit agent    Verify agent     (executors; templates/*.md)
   │           (needs operator confirmation)      │
   └───────────────┼────────────────┘
                   ▼
        ┌───────────────────────┐
        │  POLICY-GATE (Go)      │ ◄── signed scope.json (ROE)
        │  logical + egress      │
        └───────────┬───────────┘
                    ▼
        ┌───────────────────────┐
        │  SANDBOX (Go)          │  ephemeral, egress-pinned tool runs
        └───────────┬───────────┘
                    ▼
   Engagement graph (findings + tasks)  ──►  Findings/report
                    ▲
         Gateway + approval queue (operator)
```

## Data model — the engagement graph

Two node types (adapted from sapper's fact/intent hypergraph):

- **Finding** — confirmed knowledge about the target: `host`, `service`,
  `vuln`, `cred`, `loot`, `note`. Carries the `target` it concerns. This is the
  attack graph and the shared agent memory.
- **Task** — a planned unit of offensive work. A hyper-edge: it consumes one or
  more Findings (`from`) and, on conclusion, produces a new Finding (`to`).
  Carries a `risk_tier`.

`risk_tier ∈ {recon, enum, analysis, exploit, post, destructive}`. The last
three are **gated**: creating one sets `requires_confirmation`, and the task is
neither in the ready `frontier` nor claimable until an operator calls
`rt confirm`. This is the semi-autonomous model, enforced in `store.py` — not
a prompt instruction.

The store is one JSON file per node under the engagement directory, fcntl-locked
and written atomically. No database needed on the appliance for the core loop.

## Scope — the safety spine

`rt.scope.Scope` is the signed Rules of Engagement: allowed/excluded CIDRs and
domains, time window, rate cap. It is signed by the operator at engagement
creation; `rt init` refuses to start on an unsigned/invalid scope.

Enforcement is **two points, defense in depth**:

1. **Logical** — the Python orchestrator checks every target before dispatch
   (fast, early rejection), and the Go policy-gate re-checks it authoritatively.
2. **Physical** — the sandbox's only egress route is the policy-gate proxy,
   which drops traffic to any non-scoped host. A confused or compromised agent
   container *cannot* reach an excluded asset.

The Python signer and the Go verifier produce byte-identical canonical forms
(sorted keys, compact separators), so a scope signed by the operator in Python
verifies in the Go gate. This is tested on both sides.

## sapper → RT mapping

| sapper-v2 | RT | change |
|---|---|---|
| `fact` | `Finding` | typed knowledge node (kinds kept: host/service/vuln/cred/loot) |
| `intent` | `Task` | adds `risk_tier`; gating via `requires_confirmation` |
| `arena.py` (CTF platform client) | `scope.py` + policy-gate | **replaced**: signed ROE against real client assets instead of a contest API |
| tmux "fleet" of workers | commander + executors over gRPC sandbox | orchestration kept; execution moved behind the gate |
| flag ledger | `findings.py` report | CTF scoring → VAPT client deliverable |
| `kb/` | `rt/knowledge/` | kept (offline technique base) |
| prompt-injection hardening in templates | kept verbatim | sapper's "target output is untrusted data" discipline is exactly right for RT |
| — | Go policy-gate / sandbox / gateway | **net-new** (sapper is Python-only) |

## What to build next (in order)

1. **Durable workflow engine (Temporal).** An engagement must pause at the
   confirmation gate for hours and resume across an appliance reboot. Wrap each
   phase as an activity; model approval as a signal.
2. **Sandbox container runtime + egress proxy.** Make the physical scope
   boundary real (gVisor/Firecracker + the policy-gate proxy).
3. **gRPC services** from `proto/rt.proto` (orchestrator ↔ gate ↔ sandbox).
4. **Persistence + audit:** Postgres (findings, hash-chained audit log), Neo4j
   (attack graph at scale).
5. **Operator console** (`console/`): engagement view, live attack graph, and
   the approval queue backed by `gateway/`.
6. **Tool adapter library:** grow `sandbox/adapters.go` (nmap/nuclei present) —
   each adapter takes its target only from the authorized field.
