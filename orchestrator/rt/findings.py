"""
rt.findings — turn the engagement graph into a client deliverable.

sapper's output was a flag ledger for a CTF scoreboard. RT's output is a VAPT
report: a structured list of findings with severity, affected assets, and
reproduction steps, assembled live from the graph (the agents populate `vuln`
findings as they confirm them — see the templates). This module reads the
graph and renders the report; it does not re-derive anything.
"""
from __future__ import annotations

from .store import Store

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def collect_vulns(store: Store) -> list[dict]:
    vulns = [f for f in store.list_findings() if f.get("kind") == "vuln"]
    vulns.sort(key=lambda v: SEVERITY_ORDER.get(
        (v.get("data") or {}).get("severity", "info").lower(), 5))
    return vulns


def summary_counts(store: Store) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in store.list_findings():
        counts[f.get("kind", "note")] = counts.get(f.get("kind", "note"), 0) + 1
    return counts


def render_markdown(store: Store) -> str:
    project = store.load_project()
    vulns = collect_vulns(store)
    counts = summary_counts(store)
    hosts = [f for f in store.list_findings() if f.get("kind") == "host"]

    lines = [
        f"# Penetration Test Report — {project.get('engagement_id', 'engagement')}",
        "",
        f"**Objective:** {project.get('objective', '')}  ",
        f"**Scope reference:** `{project.get('scope_ref', '')}`  ",
        f"**Generated:** {project.get('created_at', '')}",
        "",
        "## Summary",
        "",
        f"- Hosts identified: {len(hosts)}",
        f"- Vulnerabilities confirmed: {len(vulns)}",
        f"- Findings by type: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "",
        "## Findings",
        "",
    ]
    if not vulns:
        lines.append("_No vulnerabilities confirmed yet._")
    for i, v in enumerate(vulns, 1):
        d = v.get("data") or {}
        sev = d.get("severity", "info").upper()
        lines += [
            f"### {i}. {v.get('title') or v['description'][:60]}  — `{sev}`",
            "",
            f"- **Affected:** {d.get('host', v.get('target', 'n/a'))}"
            + (f":{d['port']}" if d.get("port") else ""),
            f"- **CVE / class:** {d.get('cve', d.get('name', 'n/a'))}",
            f"- **Status:** {d.get('status', 'confirmed')}",
            "",
            v.get("description", ""),
            "",
        ]
        if v.get("doc"):
            lines += ["**Evidence / reproduction:**", "", v["doc"], ""]
    return "\n".join(lines)
