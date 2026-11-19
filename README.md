# RT — HexaLab's Agentic Penetration-Testing Platform

RT is a multi-agent orchestration platform for **authorized** penetration
testing, built as a **self-hosted appliance** with **semi-autonomous,
operator-gated** execution. A commander agent plans along the kill chain;
specialist executor agents run recon, enumeration, analysis, and — only after
a human operator approves — exploitation.

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY.** RT must only be run against assets
> you own or have explicit written permission to test. The signed engagement
> scope (see below) is the mechanism that enforces this.

RT's orchestration core is adapted from the MIT-licensed
[sapper-v2](https://github.com/N1nEmAn/sapper-v2); see [`NOTICE`](NOTICE).

## Why it's shaped this way

| Decision | Consequence in the code |
|---|---|
| **Self-hosted appliance** | stdlib-only Python core; model runner is swappable to a local model (`RT_AGENT_BIN`); ships offline |
| **Semi-auto, gated exploit** | `exploit`/`post`/`destructive` tasks are blocked until an operator runs `rt confirm` — enforced in the store *and* the sandbox, not in a prompt |
| **Python + Go** | Python owns agent orchestration & the graph; Go owns the safety-critical scope gate and tool sandbox |

## Layout

```
orchestrator/   Python — engagement graph, agents, prompts, findings, the `rt` CLI
  rt/store.py       the engagement graph: Finding nodes + Task edges  (ported, adapted)
  rt/scope.py       the signed Rules-of-Engagement scope  (RT-specific, safety-critical)
  rt/findings.py    graph -> VAPT report
  rt/runner.py      model-agnostic agent runner  (ported)
  rt/templates/     commander / recon / exploit / verify role prompts
policy-gate/    Go — AUTHORITATIVE scope enforcement + egress proxy (signed ROE)
sandbox/        Go — tool-execution runner; Adapter contract + nmap/nuclei examples
gateway/        Go — API + operator approval service (approval queue backend)
proto/          gRPC contract between Python and Go
deploy/         appliance composition (dev stand-in)
console/        operator UI (placeholder)
docs/           ARCHITECTURE.md
```

## Quick start

```bash
make test                      # python + go test suites

# drive an engagement from the CLI:
cd orchestrator && pip install -e .
rt scope new --engagement ACME-2026 --allow 10.0.0.0/24 --allow app.acme.test \
             --exclude 10.0.0.9/32 --file scope.json
rt scope sign --operator esmadi --file scope.json     # operator attests the ROE
rt --store .rt init --engagement ACME-2026 --objective "obtain domain admin" --scope scope.json
rt --store .rt finding "ssh 22 open" -k service --target 10.0.0.5 -d port=22
rt --store .rt task --from f001 "exploit weak ssh creds" --tier exploit --target 10.0.0.5
rt --store .rt queue                                   # shows it awaiting approval
rt --store .rt confirm t002 --operator esmadi          # the human gate
rt --store .rt report > report.md
```

## What is scaffolded vs. done

**Working now:** the engagement graph, the signed-scope model with
cross-language (Python↔Go) signature verification, the gated-exploit
confirmation flow, the **durable engagement loop** (`rt run` — auto-dispatches
ready tasks, pauses at the operator gate, resumes after `rt confirm`, and is
crash-safe because all state is on disk), the `rt` CLI, the Go policy-gate
service, the tool-adapter contract with scope/tier enforcement, and the report
generator — all with passing tests.

**Stubbed (clear interfaces, wire next):** the sandbox's container runtime and
egress proxy, the gRPC services, the operator console, and Postgres/Neo4j
persistence + the hash-chained audit log. (Temporal is an optional scale-up for
distributed workers — not required on a single appliance; see docs/ARCHITECTURE.md.)

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and the
sapper→RT mapping.
