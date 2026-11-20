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

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Status: v0.1.0](https://img.shields.io/badge/release-v0.1.0-green.svg)

This repository is the **Community Edition**, free and open source under the
[Apache License 2.0](LICENSE). RT Enterprise adds the multi-user production
gateway, scale-out persistence, branded VAPT reporting, and a supported
hardened appliance — see [`EDITIONS.md`](EDITIONS.md).

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
  rt/console.py     single-appliance operator console (approval queue, audit badge)
policy-gate/    Go — AUTHORITATIVE scope enforcement + egress proxy (signed ROE)
sandbox/        Go — tool-execution runner; Adapter contract + nmap/nuclei examples
proto/          service contract between Python and Go (HTTP+JSON; gRPC-ready)
deploy/         appliance composition — Dockerfiles, Compose, install.sh
docs/           ARCHITECTURE.md, engagement-scope / ROE template
```

## Quick start

```bash
make test                      # python + go test suites

# full end-to-end engagement against a real local target (needs curl + the
# built Go binaries): recon -> gated exploit -> operator confirm -> loot ->
# report + verified audit chain, driving the real sandbox + egress proxy.
make build && python tests/integration/run_engagement.py

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

## Install as an appliance

RT ships as a self-hosted appliance. With Docker and the Compose plugin:

```bash
# 1. create and sign an engagement scope (the Rules of Engagement)
cd orchestrator && pip install -e .
rt scope new --engagement ACME-2026 --allow 10.0.0.0/24 --allow app.acme.test \
             --exclude 10.0.0.9/32 --file ../deploy/scope/scope.json
rt scope sign --operator "$USER" --file ../deploy/scope/scope.json
cd ..

# 2. bring the appliance up (policy-gate + sandbox + console)
./deploy/install.sh up          # operator console on http://127.0.0.1:8900
```

Pre-built images are published to GHCR on each release
(`ghcr.io/eah696/rt-policy-gate`, `rt-sandbox`, `rt-orchestrator`). The console
binds to loopback and has no auth by design — on a single appliance open it
directly or over an SSH tunnel. Multi-user/network exposure is what the
Enterprise gateway is for (see [`EDITIONS.md`](EDITIONS.md)).

## What is scaffolded vs. done

**Working now:** the engagement graph, the signed-scope model with
cross-language (Python↔Go) signature verification, the gated-exploit
confirmation flow, the **durable engagement loop** (`rt run` — auto-dispatches
ready tasks, pauses at the operator gate, resumes after `rt confirm`, and is
crash-safe because all state is on disk), the `rt` CLI, the Go policy-gate
and sandbox **services** with the orchestrator wired to them over HTTP+JSON
(contract: `proto/rt.proto`) — `Python client → policy-gate` and
`Python → sandbox → policy-gate recheck`, with out-of-scope and unconfirmed-
exploit requests refused across the language boundary — the tool-adapter
contract, the **egress proxy** (physically refuses out-of-scope connections at
the network layer, delegating the decision to the policy-gate) with the
runtime abstraction that pins a tool's only egress route to it, the
**tamper-evident hash-chained audit log** (`rt audit` — every operator approval
and agent action chained by SHA-256; `verify` detects any edit, deletion, or
reorder; SQLite by default), the **single-appliance operator console**
(`rt serve` — findings by severity, the task graph, the live approval queue and
the audit chain-integrity badge), and the report generator — all with passing
tests.

**Stubbed (clear interfaces, wire next):** the `LocalRuntime` sandbox works for
dev, and the commander auto-planning loop is the next core milestone.

**RT Enterprise** (not in this repo — see [`EDITIONS.md`](EDITIONS.md)) provides
the production pieces: the hardened gVisor/Firecracker `ContainerRuntime`, the
multi-user auth/TLS gateway, scale-out persistence (Postgres for findings + the
audit log, Neo4j for attack-graph queries), and branded VAPT reporting.

**Transport note:** inter-service calls use HTTP+JSON over stdlib so the core
runs dependency-free on an air-gapped appliance. `proto/rt.proto` is the
contract; swapping to gRPC-on-the-wire is a localized change (generate stubs,
reimplement `rt/transport.py` + the Go `*Server` handlers). Temporal is an
optional scale-up for distributed workers, not required on a single appliance.
See docs/ARCHITECTURE.md.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and the
sapper→RT mapping.
