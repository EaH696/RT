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
2. **Physical** — the sandbox runs an **egress proxy** (`sandbox/egress.go`)
   that is a tool's only network route; on every connection (HTTP and CONNECT)
   it asks the policy-gate whether the destination is in scope and refuses
   otherwise. It fails CLOSED: if the gate is unreachable, the connection is
   denied. `ContainerRuntime` makes this proxy the container's *only* egress
   (nftables/transparent redirect) so even raw-socket tools cannot escape it.
   A confused or compromised agent *cannot* reach an excluded asset.

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

## Durability & the loop

`rt.engine.Engine` drives the engagement: it dispatches the ready `frontier` to
executor agents and records results back into the graph. Because every node is
a locked JSON file on disk, the loop is **crash-safe without any external
workflow engine** — construct a new Engine after a restart and it resumes from
the graph. Gated (exploit+) tasks are absent from the frontier until an operator
`rt confirm`s them, so "pause at the gate / resume after approval" falls out of
the data model rather than needing orchestration machinery. `rt run` is the CLI
entry.

**Temporal** is an *optional scale-up*, not a correctness requirement: reach for
it when you need distributed workers across many appliances or a live UI of
in-flight executions. On a single self-hosted (possibly air-gapped) appliance it
would only add a server dependency.

## Audit log — the evidence trail

`rt.audit` records every engagement action — `engagement.init`,
`task.create`, **`task.confirm`** (the operator approving offensive action),
`task.dispatch`, `task.blocked`, `task.conclude`, `finding.add` — as an
append-only, hash-chained log. Each entry stores `prev_hash` and
`entry_hash = sha256(prev_hash + canonical(entry))`, so any edit, deletion, or
reorder breaks the chain; `rt audit verify` walks it and reports the first
broken sequence number. No secret key is needed — a client or auditor verifies
it independently. This is the VAPT liability shield.

Persistence is pluggable (`AuditStore`): **SQLite** (stdlib) by default and for
the embedded appliance; a **Postgres** backend (psycopg, same schema) for
production, selected by a `postgres://` DSN via `--audit` or `open_audit()`.

## Transport between services

The Python orchestrator and the two Go services (policy-gate, sandbox) are
separate processes. `proto/rt.proto` is the contract (`PolicyGate.Check`,
`ToolRunner.Run`). The wire transport is **HTTP+JSON over stdlib** so the core
has no runtime dependency on an air-gapped appliance:

```
orchestrator ──HTTP /check──► policy-gate         (rt/transport.GateClient)
orchestrator ──HTTP /run────► sandbox ──/check──► policy-gate   (sandbox rechecks)
```

The sandbox does NOT trust that the orchestrator checked scope — it re-checks
every run against the policy-gate, and refuses gated (exploit+) tiers that are
not operator-confirmed. Both refusals are enforced in Go, across the language
boundary.

Swapping to gRPC-on-the-wire is localized: generate stubs from the proto and
reimplement `rt/transport.py` (Python) and the Go `ToolRunnerServer` /
policy-gate handler. Nothing else changes — the Engine and scope code depend
only on the client method signatures, which mirror the proto service methods.

## What to build next (in order)

1. **Wire `ContainerRuntime` to a real host.** The egress proxy and the runtime
   abstraction are done and tested; what remains is launching each tool in an
   ephemeral gVisor/Firecracker container whose only route is the proxy
   (nftables/transparent redirect). Needs a host with the runtime installed.
2. **Full graph persistence in Postgres/Neo4j.** The hash-chained audit log
   already persists (SQLite default, Postgres backend); what remains is moving
   the engagement graph (findings + tasks) off the filesystem into Postgres,
   and Neo4j for attack-graph queries at scale.
3. **Operator console — DONE for single-appliance** (`rt serve`): a stdlib web
   UI showing the engagement, findings by severity, the task graph, the live
   **approval queue** (confirm exploit tasks from the browser), and the audit
   chain-integrity badge. The Go `gateway/` remains the production edge (auth,
   TLS, multi-engagement) in front of it.
4. **Commander auto-planning:** close the loop — the commander agent proposes
   tasks from new findings; executors run them; gated ones queue to the console.
5. **Tool adapter library:** grow `sandbox/adapters.go` (nmap/nuclei present) —
   each adapter takes its target only from the authorized field — plus result
   parsers that emit typed findings.
6. **Optional / scale:** gRPC transport swap; Neo4j; Temporal for multi-appliance.
