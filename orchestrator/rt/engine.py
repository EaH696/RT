"""
rt.engine — the durable engagement loop.

This is RT's runtime: it drives the engagement graph forward by dispatching
ready tasks to executor agents and recording what comes back, and it PAUSES
automatically at the operator confirmation gate.

Why no external workflow engine (Temporal et al.) here:
    The engagement graph is already durable — every node is a locked JSON file
    on disk (rt.store). All loop state lives in the graph, so the loop is
    crash-safe for free: construct a new Engine after a restart and call run()
    and it continues from exactly where it stopped. Gated (exploit+) tasks are
    simply absent from the ready `frontier` until an operator confirms them, so
    "pause at the gate" and "resume after approval" need no special machinery —
    they fall out of the data model.

    Temporal becomes worth adding when you need distributed workers across many
    appliances or a live UI of in-flight executions; it is documented as the
    scale-up path in docs/ARCHITECTURE.md. It is NOT needed for correctness on a
    single self-hosted appliance, and it would pull a server dependency into an
    air-gapped product.

The agent is injected (a callable taking a rendered prompt and returning an
envelope {"result": "<json>"}), so the loop is testable without any model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

from . import runner as runner_mod
from .store import FINDING_KINDS, Store, frontier, awaiting_confirmation

# which role template drives each risk tier
TIER_TEMPLATE = {
    "recon": "recon", "enum": "recon", "analysis": "recon",
    "exploit": "exploit", "post": "exploit", "destructive": "exploit",
}

# An agent takes a prompt and returns a runner-style envelope {"result": str}.
AgentFn = Callable[[str], dict]


@dataclass
class StepOutcome:
    task_id: str
    status: str          # "concluded" | "rejected" | "error"
    finding_id: str | None = None
    note: str = ""


@dataclass
class RunReport:
    steps: list[StepOutcome] = field(default_factory=list)
    stopped_reason: str = ""

    @property
    def concluded(self) -> int:
        return sum(1 for s in self.steps if s.status == "concluded")


def default_agent(model: str = "local-default", timeout: int = 900) -> AgentFn:
    """Wrap rt.runner.run_agent as an AgentFn (uses RT_AGENT_BIN)."""
    def _agent(prompt: str) -> dict:
        return runner_mod.run_agent(prompt, model=model, timeout=timeout)
    return _agent


class Engine:
    def __init__(self, store: Store, agent: AgentFn, *, worker: str = "executor"):
        self.store = store
        self.agent = agent
        self.worker = worker

    # -- one unit of work -------------------------------------------------- #
    def step(self) -> StepOutcome | None:
        """Dispatch the next ready task. Returns None when nothing is ready
        (either the graph is exhausted or everything left is awaiting the
        operator gate)."""
        ready = frontier(self.store)
        if not ready:
            return None
        task = ready[0]
        tid = task["id"]
        # claim_task re-checks the gate under the store lock — defense in depth
        # against a task that became gated between frontier() and here.
        self.store.claim_task(tid, worker=self.worker)
        template = TIER_TEMPLATE.get(task.get("risk_tier", "recon"), "recon")

        from .prompts import render_task  # local import: avoids cycle at import time
        prompt = render_task(self.store, template, task)

        try:
            envelope = self.agent(prompt)
            result = envelope.get("result", "")
            payload = _parse_envelope_result(result)
        except Exception as exc:  # agent/parse failure is itself a finding
            f = self.store.add_finding(
                f"task {tid} failed to execute: {exc}", creator=self.worker,
                kind="note", target=task.get("target"), source_task=tid,
                title="execution error",
            )
            return StepOutcome(tid, "error", f["id"], str(exc))

        if not payload.get("accepted", False):
            reason = str(payload.get("reason", "no reason given"))
            f = self.store.add_finding(
                f"task {tid} rejected by executor: {reason}", creator=self.worker,
                kind="note", target=task.get("target"), source_task=tid,
                title="rejected",
            )
            return StepOutcome(tid, "rejected", f["id"], reason)

        data = payload.get("data", {}) or {}
        kind = data.get("kind", "note")
        if kind not in FINDING_KINDS:
            kind = "note"
        f = self.store.add_finding(
            description=data.get("description") or data.get("title") or "(no description)",
            creator=self.worker,
            kind=kind,
            data=data.get("data") or {},
            target=data.get("data", {}).get("host") or task.get("target"),
            title=data.get("title"),
            doc=data.get("doc"),
            source_task=tid,
        )
        return StepOutcome(tid, "concluded", f["id"])

    # -- the loop ---------------------------------------------------------- #
    def run(self, *, max_steps: int = 100) -> RunReport:
        """Run until the frontier is empty (graph done, or everything left is
        waiting on the operator gate) or max_steps is hit. Safe to call again
        after an operator confirms a gated task — it resumes."""
        report = RunReport()
        for _ in range(max_steps):
            outcome = self.step()
            if outcome is None:
                report.stopped_reason = (
                    "awaiting operator confirmation"
                    if awaiting_confirmation(self.store) else "frontier exhausted"
                )
                return report
            report.steps.append(outcome)
        report.stopped_reason = "max_steps reached"
        return report


def _parse_envelope_result(result: str) -> dict:
    """Executors return one raw JSON object. Be tolerant of leading/trailing
    prose or code fences around it."""
    if isinstance(result, dict):
        return result
    s = result.strip()
    if s.startswith("```"):
        s = s.strip("`")
        s = s[s.find("{"):]
    start = s.find("{")
    end = s.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON object in agent result: {result[:120]!r}")
    return json.loads(s[start:end + 1])
