"""Session reconstruction: group events, rebuild delegation chains."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Event


@dataclass
class Session:
    id: str
    events: list[Event] = field(default_factory=list)
    # (delegator, delegatee, event index)
    delegations: list[tuple[str, str, int]] = field(default_factory=list)

    @property
    def agents(self) -> list[str]:
        seen: list[str] = []
        for e in self.events:
            if e.agent not in seen:
                seen.append(e.agent)
        return seen

    @property
    def initiator(self) -> str | None:
        """The agent that started the session (first event's agent)."""
        return self.events[0].agent if self.events else None

    @property
    def roots(self) -> set[str]:
        """Agents authorized by construction: the initiator and any agent
        that opened the session with a session_start event."""
        roots = {e.agent for e in self.events if e.type == "session_start"}
        if self.initiator:
            roots.add(self.initiator)
        return roots

    def delegated_to(self) -> set[str]:
        return {to for _, to, _ in self.delegations}

    def total_tokens(self) -> int:
        return sum(e.tokens for e in self.events if e.type == "usage")

    def total_cost_usd(self) -> float:
        return sum(e.cost_usd for e in self.events if e.type == "usage")


def build_sessions(events: list[Event]) -> dict[str, Session]:
    sessions: dict[str, Session] = {}
    for e in events:
        s = sessions.setdefault(e.session, Session(id=e.session))
        s.events.append(e)
        if e.type == "delegation" and e.to_agent:
            s.delegations.append((e.agent, e.to_agent, e.index))
    for s in sessions.values():
        s.events.sort(key=lambda e: e.index)
    return sessions


def delegation_chain(session: Session, agent: str) -> list[str]:
    """Walk the delegation edges backwards from `agent` to the session root.

    Returns e.g. ["user", "lead", "researcher"] for agent="researcher".
    """
    parent = {to: frm for frm, to, _ in session.delegations}
    chain = [agent]
    guard = 0
    while chain[-1] in parent and guard <= len(parent):
        chain.append(parent[chain[-1]])
        guard += 1
    chain.reverse()
    return chain
