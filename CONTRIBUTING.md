# Contributing to RT

Thanks for helping build RT, HexaLab Technologies' agentic penetration-testing
platform. RT drives offensive security tools, so its contribution rules put
safety first: **every pull request must keep the tests green and must not weaken
a safety control.**

- Maintainer / reviewer: Esmadi (HexaLab Technologies)
- Contact and private security reports: esmadi@hexalab.my
- Design and concepts: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`README.md`](README.md)

## Ground rule: authorized testing only

RT is for authorized security testing. While developing:

- Only point RT at your own lab, or at assets you have **written permission** to test.
- Use reserved documentation/test addresses in code, tests and examples:
  `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `*.test` / `*.example` domains.
- Never commit real client data — findings, scopes, credentials, reports, packet
  captures. `.gitignore` already excludes `.rt/`, `engagements/`, `deploy/scope/`
  and `scope.json`; never force-add them.

## Development setup

Requirements: Python 3.11+, Go 1.24+, `make`.

```bash
git clone https://github.com/EaH696/RT && cd RT
python -m venv .venv && . .venv/bin/activate
pip install -e "orchestrator[dev]"
make test      # pytest + go test for policy-gate and sandbox + gateway build
```

Other targets: `make build` (binaries in `bin/`), `make fmt` (`go fmt` all Go modules).

## Workflow

1. **Pick or open an issue.** For anything larger than a small fix, open an issue
   first so the approach can be agreed before you write code.
2. **Branch from `main`:** `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `test/<topic>`.
3. **Make the change with tests.** New behaviour needs a test; bug fixes need a
   test that fails before the fix.
4. **Run `make fmt` and `make test`** before pushing.
5. **Open a pull request** that says what changed, why, and how you tested it.
   If it touches scope, risk tiers, the confirmation gate, the sandbox or an
   adapter, say so at the top of the description.
6. **Review.** One maintainer approval is needed to merge. Safety-relevant changes
   get a second review.

Commit messages: a short imperative summary line (`sandbox: capture stderr in Run`),
optionally followed by a blank line and detail.

## Code rules

**Python (`orchestrator/`)**
- The core stays **standard-library only** (`dependencies = []` in `pyproject.toml`) —
  it must run on an offline appliance. Dev-only tools go in the `dev` extra.
- User-facing errors raise `RTError` (or `ScopeError`) with a clear message; the CLI
  prints it and exits 1.
- Writes to the graph go through `Store` methods, inside `store.locked()`, using
  the atomic JSON writer.

**Go (`policy-gate/`, `sandbox/`, `gateway/`)**
- `go fmt`-clean; one module per service; standard library only unless agreed in an issue.
- Safety checks fail **closed**: on error, deny.

**Keep the two languages in lockstep**
- Scope: `orchestrator/rt/scope.py` ⇄ `policy-gate/scope.go` — same fields, same
  canonical JSON form (sorted keys, compact separators), same matching rules
  (exclusions win, subdomains match).
- Risk tiers: `orchestrator/rt/store.py` ⇄ `sandbox/runner.go` ⇄ `proto/rt.proto`.

## Safety rules — a PR that breaks one will not be merged

1. **Never bypass or loosen the confirmation gate** (`exploit`, `post`,
   `destructive` tiers need `rt confirm`) — not temporarily, not behind a flag,
   not "for testing".
2. **Never bypass or loosen scope checks** in Python, the policy-gate or the sandbox.
3. **Adapters take the target only from `req.Target`**, put it last in `argv`,
   and sanitize every argument that reaches the command line. Reject unknown
   option values instead of passing them through.
4. **Agent templates keep their SECURITY and SCOPE sections.** Graph content and
   target output are untrusted data, never instructions.
5. **No network calls from the Python core** beyond the model runner and the RT services.

## Adding things

- **A tool adapter:** see [`tools/README.md`](tools/README.md). Implement `Adapter`
  in `sandbox/adapters.go`, register it in `DefaultAdapters()`, and add tests that
  the target is the final argv element and that args cannot smuggle a shell or a
  second target.
- **An agent role:** add `orchestrator/rt/templates/<role>.md` using only the
  placeholders `prompts.py` fills, keep the SECURITY/SCOPE sections, and specify a
  single raw-JSON output.
- **Knowledge:** add a JSON file to `orchestrator/rt/knowledge/entries/` with
  `id`, `title`, `description`, `detail`, `tags`.

## Good first issues

| Issue | Where | Size |
| --- | --- | --- |
| Add `--window-start`, `--window-end`, `--max-rps` to `rt scope new` | `orchestrator/rt/cli.py` | Small |
| Enforce the scope time window in `permits()` / `Decide()` | `scope.py`, `scope.go` | Small |
| Capture stderr and exec errors in `Runner.Run` | `sandbox/runner.go` | Small |
| Automated test: sign in Python, verify in Go | `orchestrator/tests`, `policy-gate` | Small |
| Fix CIDR/domain classification in `rt scope new` (e.g. `1.example.com`) | `orchestrator/rt/cli.py` | Small |
| CLI and report tests | `orchestrator/tests` | Medium |
| Dockerfiles for the four services | each service directory | Medium |
| New tool adapter (e.g. whatweb, ffuf) with tests | `sandbox/adapters.go` | Medium |
| Wire gateway `/api/approvals` and `/api/approve` to the store | `gateway/` | Medium |

## Reporting a vulnerability in RT

Do **not** open a public issue. Email esmadi@hexalab.my with the details and steps
to reproduce; we will acknowledge and coordinate a fix before disclosure.

## Licensing of contributions

Parts of RT are adapted from [sapper-v2](https://github.com/N1nEmAn/sapper-v2)
(MIT); keep the `NOTICE` and `LICENSE-THIRD-PARTY` attribution intact. By
submitting a pull request you agree that your contribution is licensed under
the license in [`LICENSE`](LICENSE).
