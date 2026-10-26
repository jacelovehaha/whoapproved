"""Report rendering: Markdown and JSON audit reports, session timelines."""

from __future__ import annotations

import json
from dataclasses import asdict

from .graph import Session, delegation_chain
from .model import infer_data_class
from .rules import SEVERITY_ORDER, Finding

_ICON = {
    "session_start": "▶", "session_end": "■", "delegation": "➜",
    "tool_call": "⚙", "tool_result": "↩", "human_approval": "✔",
    "message": "✉", "usage": "Σ", "error": "✖",
}


def timeline_lines(session: Session) -> list[str]:
    lines = []
    for e in session.events:
        icon = _ICON.get(e.type, "·")
        detail = ""
        if e.type == "delegation":
            detail = f"delegates to {e.to_agent}"
        elif e.type == "tool_call":
            cls = infer_data_class(e)
            detail = f"{e.tool}" + (f" (data: {cls})" if cls else "")
        elif e.type == "human_approval":
            detail = f"approved by {e.approved_by} scope={e.scope}"
        elif e.type == "usage":
            detail = f"tokens={e.tokens} cost=${e.cost_usd:.4f}"
        elif e.type == "message":
            detail = f"message to {e.raw.get('to', '?')}"
        lines.append(f"{e.ts}  {icon} [{e.agent}] {detail}".rstrip())
    return lines


def render_json(sessions: dict[str, Session], findings: list[Finding]) -> str:
    payload = {
        "sessions": [
            {
                "id": s.id,
                "agents": s.agents,
                "initiator": s.initiator,
                "events": len(s.events),
                "tokens": s.total_tokens(),
                "cost_usd": round(s.total_cost_usd(), 6),
                "delegation_chains": {a: delegation_chain(s, a) for a in s.agents},
            }
            for s in sessions.values()
        ],
        "findings": [asdict(f) for f in findings],
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f.severity == sev)
                for sev in ("critical", "high", "medium", "low")
            },
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(sessions: dict[str, Session], findings: list[Finding],
                     source: str = "") -> str:
    out: list[str] = ["# whoapproved — audit report", ""]
    if source:
        out += [f"Source: `{source}`", ""]
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    out += [
        f"**{len(findings)} finding(s)** across {len(sessions)} session(s) "
        f"({crit} critical, {high} high).",
        "",
        "## Sessions",
        "",
        "| session | initiator | agents | events | tokens | cost |",
        "|---|---|---|---|---|---|",
    ]
    for s in sessions.values():
        out.append(
            f"| {s.id} | {s.initiator} | {', '.join(s.agents)} | {len(s.events)} "
            f"| {s.total_tokens()} | ${s.total_cost_usd():.4f} |"
        )
    out += ["", "## Findings", ""]
    if not findings:
        out.append("No findings. Every sensitive action in these traces was covered "
                   "by a prior human approval, and every acting agent traces back "
                   "to a recorded delegation.")
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
        out += [
            f"### [{f.severity.upper()}] {f.rule}",
            "",
            f"- session `{f.session}`, agent `{f.agent}`, event #{f.event_index}",
            f"- {f.message}",
            "",
        ]
    out += ["## Timelines", ""]
    for s in sessions.values():
        out += [f"### Session `{s.id}`", "", "```text"]
        out += timeline_lines(s)
        out += ["```", ""]
    return "\n".join(out)
