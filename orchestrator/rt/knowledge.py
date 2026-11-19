"""
rt.knowledge — offline technique / CVE knowledge base.

Ported from sapper-v2's kb (MIT, (c) 2026 N1nEmAn; see /NOTICE). Entries are
JSON files under rt/knowledge/entries. On a self-hosted appliance this ships
pre-loaded so agents can look up methodology without internet access.
"""
from __future__ import annotations

import json
from pathlib import Path

ENTRIES_DIR = Path(__file__).parent / "knowledge" / "entries"


def load_all() -> list[dict]:
    if not ENTRIES_DIR.exists():
        return []
    return sorted((json.loads(p.read_text(encoding="utf-8"))
                   for p in ENTRIES_DIR.glob("*.json")), key=lambda e: e["id"])


def search(query: str, tag: str | None = None, limit: int = 5) -> list[dict]:
    terms = [w for w in query.lower().split() if w]
    scored = []
    for e in load_all():
        if tag and tag not in e.get("tags", []):
            continue
        hay = " ".join([e.get("title", ""), e.get("description", ""),
                        e.get("detail", ""), " ".join(e.get("tags", []))]).lower()
        score = sum(hay.count(t) for t in terms)
        if score:
            scored.append((score, e))
    scored.sort(key=lambda x: -x[0])
    return [e for _, e in scored[:limit]]
