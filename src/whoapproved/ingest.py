"""Trace ingestion: native JSONL traces and MCP JSON-RPC logs."""

from __future__ import annotations

import json
from pathlib import Path

from .model import Event, parse_event


def load_jsonl(path: str | Path) -> list[Event]:
    """Load a native whoapproved JSONL trace."""
    events: list[Event] = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"line {lineno}: invalid JSON ({e})") from e
        try:
            events.append(parse_event(obj, index=len(events)))
        except ValueError as e:
            raise ValueError(f"line {lineno}: {e}") from e
    return events


def adapt_mcp_record(obj: dict, index: int) -> Event | None:
    """Convert one MCP JSON-RPC record into an Event, or None if not auditable.

    Expected record shape (as produced by MCP hosts / proxies that log traffic):

        {"ts": ..., "session": ..., "agent": ...,
         "jsonrpc": "2.0", "method": "tools/call",
         "params": {"name": "fs.read", "arguments": {...}}}

    Responses (records with "result"/"error" and an "id") map to tool_result.
    """
    if not isinstance(obj, dict) or "method" not in obj and "result" not in obj:
        return None
    ts = str(obj.get("ts", ""))
    session = str(obj.get("session", "mcp-session"))
    agent = str(obj.get("agent", "mcp-client"))
    method = obj.get("method")
    if method == "tools/call":
        params = obj.get("params") or {}
        return Event(
            index=index, ts=ts, session=session, agent=agent, type="tool_call",
            tool=params.get("name"), args=params.get("arguments") or {}, raw=obj,
        )
    if method is None and ("result" in obj or "error" in obj):
        return Event(
            index=index, ts=ts, session=session, agent=agent, type="tool_result",
            tool=obj.get("tool"), raw=obj,
        )
    return None


def load_mcp_log(path: str | Path) -> list[Event]:
    """Load an MCP JSON-RPC log (JSONL), keeping only auditable records."""
    events: list[Event] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev = adapt_mcp_record(obj, index=len(events))
        if ev is not None:
            events.append(ev)
    return events
