"""Event model for agent traces.

A trace is a JSONL stream of events. Every event carries at minimum:

    ts       ISO-8601 timestamp (string, kept as-is; ordering uses file order)
    session  session / trace identifier grouping one unit of work
    agent    name of the agent that emitted the event ("user" for the human)
    type     one of EVENT_TYPES

Type-specific fields:

    delegation      to_agent, task
    tool_call       tool, args (object), data_class (public|internal|private|secret)
    tool_result     tool, ok
    human_approval  approved_by, scope (list of tool names / patterns / "*")
    message         to, text
    usage           tokens, cost_usd
    error           message
"""

from __future__ import annotations

from dataclasses import dataclass, field

EVENT_TYPES = {
    "session_start",
    "session_end",
    "delegation",
    "tool_call",
    "tool_result",
    "human_approval",
    "message",
    "usage",
    "error",
}

DATA_CLASSES = {"public", "internal", "private", "secret"}


@dataclass
class Event:
    index: int
    ts: str
    session: str
    agent: str
    type: str
    tool: str | None = None
    args: dict = field(default_factory=dict)
    data_class: str | None = None
    to_agent: str | None = None
    approved_by: str | None = None
    scope: list = field(default_factory=list)
    tokens: int = 0
    cost_usd: float = 0.0
    raw: dict = field(default_factory=dict)


def parse_event(obj: dict, index: int) -> Event:
    """Validate and build an Event from a decoded JSON object."""
    if not isinstance(obj, dict):
        raise ValueError(f"event {index}: expected a JSON object")
    for key in ("ts", "session", "agent", "type"):
        if key not in obj:
            raise ValueError(f"event {index}: missing required field {key!r}")
    etype = obj["type"]
    if etype not in EVENT_TYPES:
        raise ValueError(
            f"event {index}: unknown type {etype!r} (expected one of {sorted(EVENT_TYPES)})"
        )
    data_class = obj.get("data_class")
    if data_class is not None and data_class not in DATA_CLASSES:
        raise ValueError(f"event {index}: invalid data_class {data_class!r}")
    args = obj.get("args") or {}
    if not isinstance(args, dict):
        raise ValueError(f"event {index}: 'args' must be an object")
    scope = obj.get("scope") or []
    if not isinstance(scope, list):
        raise ValueError(f"event {index}: 'scope' must be a list")
    return Event(
        index=index,
        ts=str(obj["ts"]),
        session=str(obj["session"]),
        agent=str(obj["agent"]),
        type=etype,
        tool=obj.get("tool"),
        args=args,
        data_class=data_class,
        to_agent=obj.get("to_agent"),
        approved_by=obj.get("approved_by"),
        scope=[str(s) for s in scope],
        tokens=int(obj.get("tokens") or 0),
        cost_usd=float(obj.get("cost_usd") or 0.0),
        raw=obj,
    )


# Substrings that mark a tool as sensitive (state-changing or privileged)
# and as an egress path (data can leave the system boundary).
SENSITIVE_PATTERNS = (
    "exec", "shell", "bash", "powershell", "write", "delete", "remove",
    "send", "post", "pay", "transfer", "deploy", "publish", "grant",
    "chmod", "sudo", "update", "create", "drop",
)

EGRESS_PATTERNS = (
    "send", "post", "upload", "webhook", "email", "publish", "push",
)

SECRET_ARG_MARKERS = (".ssh", "id_rsa", ".env", "credentials", "private_key", "/etc/shadow")


def is_sensitive_tool(tool: str | None) -> bool:
    if not tool:
        return False
    t = tool.lower()
    return any(p in t for p in SENSITIVE_PATTERNS)


def is_egress_tool(tool: str | None) -> bool:
    if not tool:
        return False
    t = tool.lower()
    return any(p in t for p in EGRESS_PATTERNS)


def infer_data_class(event: Event) -> str | None:
    """Explicit data_class wins; otherwise infer 'secret' from argument markers."""
    if event.data_class:
        return event.data_class
    blob = str(event.args).lower()
    if any(m in blob for m in SECRET_ARG_MARKERS):
        return "secret"
    return None
