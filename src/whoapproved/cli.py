"""Command-line interface.

    whoapproved audit trace.jsonl [--format md|json] [--out report.md]
                                  [--budget-tokens N] [--budget-usd X]
                                  [--fail-on critical|high|medium|low|any]
    whoapproved audit mcplog.jsonl --mcp
    whoapproved timeline trace.jsonl [--session ID]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .graph import build_sessions
from .ingest import load_jsonl, load_mcp_log
from .model import Event
from .report import render_json, render_markdown, timeline_lines
from .rules import SEVERITY_ORDER, AuditConfig, audit_session


def _load(path: str, mcp: bool) -> list[Event]:
    return load_mcp_log(path) if mcp else load_jsonl(path)


def cmd_audit(args: argparse.Namespace) -> int:
    events = _load(args.trace, args.mcp)
    sessions = build_sessions(events)
    cfg = AuditConfig(budget_tokens=args.budget_tokens, budget_usd=args.budget_usd)
    findings = []
    for s in sessions.values():
        findings.extend(audit_session(s, cfg))
    text = (render_json(sessions, findings) if args.format == "json"
            else render_markdown(sessions, findings, source=args.trace))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"report written to {args.out}: {len(findings)} finding(s)")
    else:
        print(text)
    if args.fail_on == "any":
        return 1 if findings else 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


def cmd_timeline(args: argparse.Namespace) -> int:
    events = _load(args.trace, args.mcp)
    sessions = build_sessions(events)
    for sid, s in sessions.items():
        if args.session and sid != args.session:
            continue
        print(f"== session {sid} (initiator: {s.initiator}) ==")
        for line in timeline_lines(s):
            print(line)
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="whoapproved",
        description="Flight recorder and approval auditor for multi-agent systems.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("audit", help="audit a trace and report findings")
    pa.add_argument("trace", help="path to a JSONL trace (or MCP log with --mcp)")
    pa.add_argument("--mcp", action="store_true", help="input is an MCP JSON-RPC log")
    pa.add_argument("--format", choices=("md", "json"), default="md")
    pa.add_argument("--out", help="write the report to this file instead of stdout")
    pa.add_argument("--budget-tokens", type=int, default=None)
    pa.add_argument("--budget-usd", type=float, default=None)
    pa.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "any"),
                    default="high",
                    help="exit 1 when a finding at or above this severity exists")
    pa.set_defaults(func=cmd_audit)

    pt = sub.add_parser("timeline", help="print a reconstructed session timeline")
    pt.add_argument("trace")
    pt.add_argument("--mcp", action="store_true")
    pt.add_argument("--session", default=None)
    pt.set_defaults(func=cmd_timeline)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
