"""Audit rules — the guardian checks.

Each rule inspects one reconstructed session and returns Findings.
Severities: low < medium < high < critical.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field

from .graph import Session
from .model import Event, infer_data_class, is_egress_tool, is_sensitive_tool

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PRIVATE_CLASSES = {"private", "secret"}


@dataclass
class Finding:
    rule: str
    severity: str
    session: str
    agent: str
    event_index: int
    message: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AuditConfig:
    loop_threshold: int = 5
    budget_tokens: int | None = None
    budget_usd: float | None = None


def _scope_covers(scope: list[str], tool: str) -> bool:
    return any(s == "*" or fnmatch.fnmatchcase(tool, s) for s in scope)


def _approvals_before(session: Session, index: int) -> list[Event]:
    return [e for e in session.events if e.type == "human_approval" and e.index < index]


def rule_sensitive_actions(session: Session, cfg: AuditConfig) -> list[Finding]:
    """Sensitive tool calls must be covered by a *prior* human approval.

    Two flavours:
    - unapproved-sensitive-action: no approval exists before the call at all.
    - approval-scope-mismatch: approvals exist, but none covers this tool —
      the approval was effectively laundered onto an action nobody approved.
    """
    out: list[Finding] = []
    for e in session.events:
        if e.type != "tool_call" or not is_sensitive_tool(e.tool):
            continue
        approvals = _approvals_before(session, e.index)
        if any(_scope_covers(a.scope, e.tool or "") for a in approvals):
            continue
        if approvals:
            out.append(Finding(
                rule="approval-scope-mismatch", severity="high",
                session=session.id, agent=e.agent, event_index=e.index,
                message=(f"Sensitive call {e.tool!r} by agent {e.agent!r} is not covered by "
                         f"any prior approval (approved scopes: "
                         f"{sorted({s for a in approvals for s in a.scope})})."),
                evidence={"tool": e.tool, "approvals": [a.index for a in approvals]},
            ))
        else:
            out.append(Finding(
                rule="unapproved-sensitive-action", severity="high",
                session=session.id, agent=e.agent, event_index=e.index,
                message=(f"Sensitive call {e.tool!r} by agent {e.agent!r} has no prior "
                         f"human approval in this session."),
                evidence={"tool": e.tool},
            ))
    return out


def rule_orphan_delegation(session: Session, cfg: AuditConfig) -> list[Finding]:
    """Every acting agent must trace back to the session initiator via a
    recorded delegation. An agent that appears and acts with no delegation
    edge is a broken chain of authority (or a trace you cannot trust)."""
    out: list[Finding] = []
    initiator = session.initiator
    delegated = session.delegated_to()
    roots = session.roots
    acting = {e.agent for e in session.events if e.type == "tool_call"}
    for agent in sorted(acting):
        if agent in roots or agent in delegated:
            continue
        first = min(e.index for e in session.events if e.agent == agent and e.type == "tool_call")
        out.append(Finding(
            rule="orphan-delegation", severity="medium",
            session=session.id, agent=agent, event_index=first,
            message=(f"Agent {agent!r} performs tool calls in session {session.id!r} but no "
                     f"delegation to it was recorded (initiator: {initiator!r})."),
            evidence={"initiator": initiator},
        ))
    return out


def rule_exfiltration_path(session: Session, cfg: AuditConfig) -> list[Finding]:
    """The lethal trifecta, as a trace query: a private/secret read followed
    later in the same session by an egress tool call."""
    out: list[Finding] = []
    reads: list[Event] = []
    for e in session.events:
        if e.type != "tool_call":
            continue
        cls = infer_data_class(e)
        if cls in PRIVATE_CLASSES:
            reads.append(e)
        elif is_egress_tool(e.tool) and reads:
            first = reads[0]
            out.append(Finding(
                rule="exfiltration-path", severity="critical",
                session=session.id, agent=e.agent, event_index=e.index,
                message=(f"Private data read ({first.tool!r}, class={infer_data_class(first)}) "
                         f"by {first.agent!r} is followed by egress call {e.tool!r} "
                         f"by {e.agent!r} in the same session."),
                evidence={"read_event": first.index, "read_tool": first.tool,
                          "egress_tool": e.tool},
            ))
            reads = []  # one finding per read-batch is enough
    return out


def rule_runaway_loop(session: Session, cfg: AuditConfig) -> list[Finding]:
    """Same tool with identical arguments called >= threshold times."""
    out: list[Finding] = []
    counts: dict[tuple[str, str], list[int]] = {}
    for e in session.events:
        if e.type != "tool_call":
            continue
        key = (e.tool or "", json.dumps(e.args, sort_keys=True, default=str))
        counts.setdefault(key, []).append(e.index)
    for (tool, _), idxs in counts.items():
        if len(idxs) >= cfg.loop_threshold:
            out.append(Finding(
                rule="runaway-loop", severity="medium",
                session=session.id, agent=session.events[idxs[0]].agent,
                event_index=idxs[0],
                message=(f"Tool {tool!r} called with identical arguments {len(idxs)} times "
                         f"in session {session.id!r} (threshold {cfg.loop_threshold})."),
                evidence={"tool": tool, "count": len(idxs), "events": idxs},
            ))
    return out


def rule_budget(session: Session, cfg: AuditConfig) -> list[Finding]:
    out: list[Finding] = []
    tokens = session.total_tokens()
    cost = session.total_cost_usd()
    if cfg.budget_tokens is not None and tokens > cfg.budget_tokens:
        out.append(Finding(
            rule="budget-blowout", severity="medium",
            session=session.id, agent=session.initiator or "", event_index=session.events[-1].index,
            message=f"Session used {tokens} tokens, over the budget of {cfg.budget_tokens}.",
            evidence={"tokens": tokens, "budget_tokens": cfg.budget_tokens},
        ))
    if cfg.budget_usd is not None and cost > cfg.budget_usd:
        out.append(Finding(
            rule="budget-blowout", severity="medium",
            session=session.id, agent=session.initiator or "", event_index=session.events[-1].index,
            message=f"Session cost ${cost:.4f}, over the budget of ${cfg.budget_usd:.4f}.",
            evidence={"cost_usd": cost, "budget_usd": cfg.budget_usd},
        ))
    return out


ALL_RULES = (
    rule_sensitive_actions,
    rule_orphan_delegation,
    rule_exfiltration_path,
    rule_runaway_loop,
    rule_budget,
)


def audit_session(session: Session, cfg: AuditConfig | None = None) -> list[Finding]:
    cfg = cfg or AuditConfig()
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(session, cfg))
    findings.sort(key=lambda f: (f.event_index, -SEVERITY_ORDER[f.severity]))
    return findings
