"""
rt.engine — the orchestration loop that closes the commander/executor cycle.

This is the missing driver that turns RT's parts into a semi-autonomous loop:

    plan()  — render the COMMANDER prompt against the live engagement graph,
              run the agent, parse the tasks it proposes, scope-check and
              de-duplicate them, and write the survivors to the store.
    step()  — dispatch every READY task on the frontier to the matching
              executor agent (recon/verify/exploit). frontier() already
              excludes gated (exploit+) tasks that an operator has not yet
              `rt confirm`ed, so the human gate falls out of the data model —
              the loop simply never sees an unconfirmed gated task.
    run()   — plan → step, round after round, until the commander proposes no
              new work and the frontier is empty (objective exhausted), or only
              unconfirmed gated tasks remain (pause for the operator).

Safety posture: the COMMANDER only *proposes*. The Engine disposes — it is the
Engine, not the LLM, that re-checks every proposed target against the signed
scope before a task is ever persisted. This is defense-in-depth on top of the
Go policy-gate, never a replacement for it. All graph/agent text is untrusted
data (see templates/*.md); the parser below treats the agent's output as data,
not instructions.

The agent runner is injectable (``agent=`` ctor arg) so the loop is testable
without a live model and so an appliance can point RT at a locally served model
(see rt.runner / RT_AGENT_BIN).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .prompts import render, render_task
from .runner import run_agent
from .scope import Scope
from .store import Store, frontier, awaiting_confirmation, is_open

# risk_tier -> executor role template (templates/<name>.md)
TIER_TEMPLATE = {
    "recon": "recon",
    "enum": "recon",
    "analysis": "verify",
    "exploit": "exploit",
    "post": "exploit",
    "destructive": "exploit",
}

AgentFn = Callable[..., dict]


def _strip_fences(text: str) -> str:
    """Remove a ```json ... ``` (or bare ```) fence if the agent wrapped its JSON."""
    t = text.strip()
    m = re.match(r"^```[a-zA-Z0-9_-]*\s*(.*?)\s*```$", t, re.DOTALL)
    return m.group(1).strip() if m else t


def _first_json_object(text: str) -> str | None:
    """Return the first balanced {...} object in text, ignoring braces in strings."""
    start = text.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def parse_tasks(result: str) -> list[dict]:
    """Tolerantly extract the commander's ``{"tasks": [...]}`` proposal.

    Accepts a raw JSON object, a fenced block, or JSON embedded in prose.
    Returns a list of normalized specs; never raises on malformed model output
    (returns []), because the agent's output is untrusted data.
    """
    if not result or not result.strip():
        return []
    candidate = _strip_fences(result)
    if not candidate.lstrip().startswith("{"):
        candidate = _first_json_object(candidate) or ""
    try:
        obj = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(obj, dict):
        return []
    raw = obj.get("tasks", [])
    if not isinstance(raw, list):
        return []
    specs: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        desc = str(item.get("description", "")).strip()
        if not desc:
            continue
        frm = item.get("from", [])
        if isinstance(frm, str):
            frm = [frm]
        if not isinstance(frm, list) or not frm:
            continue
        specs.append({
            "from": [str(x) for x in frm],
            "description": desc,
            "tier": str(item.get("tier", "recon")).strip() or "recon",
            "target": (str(item["target"]).strip() if item.get("target") else None),
            "title": (str(item["title"]).strip() if item.get("title") else None),
        })
    return specs


@dataclass
class RoundResult:
    created: list[str] = field(default_factory=list)      # task ids created by plan()
    dispatched: list[str] = field(default_factory=list)   # task ids run by step()
    skipped_scope: list[str] = field(default_factory=list)  # proposals refused (out of scope)
    pending_confirmation: list[str] = field(default_factory=list)  # gated, awaiting operator


class Engine:
    """Drives one engagement's commander/executor loop over the shared graph."""

    def __init__(
        self,
        store: Store,
        scope: Scope,
        model: str,
        *,
        agent: AgentFn = run_agent,
        timeout: int = 900,
    ):
        self.store = store
        self.scope = scope
        self.model = model
        self._agent = agent
        self.timeout = timeout
        self._attempted: set[str] = set()  # task ids dispatched in the current run()

    # -- commander: propose work ------------------------------------------- #
    def plan(self) -> RoundResult:
        res = RoundResult()
        envelope = self._agent(
            render(self.store, "command"), model=self.model, timeout=self.timeout,
        )
        for spec in parse_tasks(envelope.get("result", "")):
            target = spec["target"]
            # The Engine — not the LLM — enforces scope before any write.
            if target is not None and not self.scope.permits(target):
                res.skipped_scope.append(target)
                continue
            if self._duplicate_open_task(spec):
                continue
            try:
                task = self.store.add_task(
                    spec["from"], spec["description"], creator="commander",
                    risk_tier=spec["tier"], target=target, title=spec["title"],
                )
            except Exception:
                # store rejects (unknown finding, gated-without-target, bad tier):
                # the proposal is dropped, not fatal to the loop.
                continue
            res.created.append(task["id"])
        return res

    # -- executors: do ready work ------------------------------------------ #
    def step(self, res: RoundResult | None = None) -> RoundResult:
        res = res or RoundResult()
        for task in frontier(self.store):
            # Don't re-dispatch a task already attempted this run: an executor
            # that fails to conclude its task leaves it open on the frontier,
            # and we must not spin on it.
            if task["id"] in self._attempted:
                continue
            self._attempted.add(task["id"])
            template = TIER_TEMPLATE.get(task["risk_tier"], "recon")
            self.store.claim_task(task["id"], worker=template)
            prompt = render_task(self.store, template, task)
            # The executor records its own findings via the `rt` CLI (the sapper
            # model). It is told which engagement store to write to via env; the
            # findings it writes are picked up when the next round re-reads graph.
            env_note = f"Use the rt CLI with --store {self.store.root} for all graph writes."
            self._agent(
                prompt, model=self.model, timeout=self.timeout,
                cwd=self.store.root.parent, append_system=env_note,
            )
            res.dispatched.append(task["id"])
        return res

    # -- the loop ---------------------------------------------------------- #
    def run(self, *, max_rounds: int = 20) -> list[RoundResult]:
        self._attempted = set()
        history: list[RoundResult] = []
        for _ in range(max_rounds):
            res = self.plan()
            self.step(res)
            res.pending_confirmation = [t["id"] for t in awaiting_confirmation(self.store)]
            history.append(res)
            # Stop when the round neither created a task nor dispatched one. A
            # frontier that still holds only already-attempted or unconfirmed
            # gated tasks is a reason to pause (for the operator), not to spin.
            if not res.created and not res.dispatched:
                break
        return history

    # -- helpers ----------------------------------------------------------- #
    def _duplicate_open_task(self, spec: dict) -> bool:
        key = (spec["tier"], spec["target"], spec["description"].lower())
        for t in self.store.list_tasks():
            if not is_open(t):
                continue
            if (t.get("risk_tier"), t.get("target"),
                    (t.get("description") or "").lower()) == key:
                return True
        return False
