"""
rt.prompts — render an agent role template against the current engagement graph.

Ported from sapper-v2's render_prompt (MIT, (c) 2026 N1nEmAn; see /NOTICE).
Single-pass {placeholder} substitution with a regex so graph content that
happens to contain braces cannot rewrite a later token.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .store import Store, is_open

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _graph_yaml(store: Store) -> str:
    findings = store.list_findings()
    tasks = store.list_tasks()
    lines = ["findings:"]
    for f in findings:
        lines.append(f"  - id: {f['id']}  kind: {f.get('kind')}  "
                     f"target: {f.get('target')}  :: {f.get('title') or f['description'][:60]}")
    lines.append("open_tasks:")
    for t in tasks:
        if is_open(t):
            gate = " [NEEDS CONFIRMATION]" if (
                t.get("requires_confirmation") and not t.get("confirmed_at")) else ""
            lines.append(f"  - id: {t['id']}  tier: {t.get('risk_tier')}  "
                         f"target: {t.get('target')}{gate} :: "
                         f"{t.get('title') or t['description'][:60]}")
    return "\n".join(lines)


def _replace(template_text: str, replacements: dict[str, str]) -> str:
    return re.sub(
        r"\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda m: replacements.get(m.group(1), m.group(0)),
        template_text,
    )


def render(store: Store, template: str) -> str:
    text = (TEMPLATES_DIR / f"{template}.md").read_text(encoding="utf-8")
    p = store.load_project()
    return _replace(text, {
        "objective": p.get("objective", ""),
        "engagement_id": p.get("engagement_id", ""),
        "scope_ref": p.get("scope_ref", ""),
        "graph_yaml": _graph_yaml(store),
    })


def render_task(store: Store, template: str, task: dict) -> str:
    text = (TEMPLATES_DIR / f"{template}.md").read_text(encoding="utf-8")
    return _replace(text, {
        "graph_yaml": _graph_yaml(store),
        "task_id": task["id"],
        "task_description": task.get("description", ""),
        "task_target": task.get("target") or "",
        "risk_tier": task.get("risk_tier", ""),
    })
