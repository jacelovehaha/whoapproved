import unittest
from pathlib import Path

from whoapproved.graph import build_sessions
from whoapproved.ingest import load_jsonl
from whoapproved.model import parse_event
from whoapproved.rules import AuditConfig, audit_session

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def session_from(objs, sid="t"):
    events = [parse_event(o, i) for i, o in enumerate(objs)]
    return build_sessions(events)[sid]


def ev(agent, type, **kw):
    base = {"ts": "2026-10-27T00:00:00Z", "session": "t", "agent": agent, "type": type}
    base.update(kw)
    return base


class TestExampleTraces(unittest.TestCase):
    def test_clean_trace_has_zero_findings(self):
        sessions = build_sessions(load_jsonl(EXAMPLES / "clean.jsonl"))
        findings = [f for s in sessions.values() for f in audit_session(s)]
        self.assertEqual(findings, [])

    def test_incident_trace_findings(self):
        sessions = build_sessions(load_jsonl(EXAMPLES / "incident.jsonl"))
        findings = [f for s in sessions.values() for f in audit_session(s)]
        rules = [f.rule for f in findings]
        self.assertEqual(len(findings), 5, rules)
        self.assertIn("exfiltration-path", rules)
        self.assertIn("runaway-loop", rules)
        self.assertIn("orphan-delegation", rules)
        self.assertEqual(rules.count("unapproved-sensitive-action"), 2)
        crit = [f for f in findings if f.severity == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].rule, "exfiltration-path")


class TestSensitiveActions(unittest.TestCase):
    def test_approval_after_call_does_not_count(self):
        s = session_from([
            ev("a", "session_start"),
            ev("a", "tool_call", tool="fs.write"),
            ev("user", "human_approval", approved_by="u", scope=["fs.write"]),
        ])
        rules = [f.rule for f in audit_session(s)]
        self.assertIn("unapproved-sensitive-action", rules)

    def test_scope_mismatch(self):
        s = session_from([
            ev("a", "session_start"),
            ev("user", "human_approval", approved_by="u", scope=["fs.read"]),
            ev("a", "tool_call", tool="fs.write"),
        ])
        rules = [f.rule for f in audit_session(s)]
        self.assertIn("approval-scope-mismatch", rules)
        self.assertNotIn("unapproved-sensitive-action", rules)

    def test_wildcard_scope_covers(self):
        s = session_from([
            ev("a", "session_start"),
            ev("user", "human_approval", approved_by="u", scope=["fs.*"]),
            ev("a", "tool_call", tool="fs.write"),
        ])
        self.assertEqual(audit_session(s), [])


class TestBudget(unittest.TestCase):
    def test_budget_blowout(self):
        s = session_from([
            ev("a", "session_start"),
            ev("a", "usage", tokens=100, cost_usd=0.5),
        ])
        findings = audit_session(s, AuditConfig(budget_tokens=50))
        self.assertEqual([f.rule for f in findings], ["budget-blowout"])
        findings = audit_session(s, AuditConfig(budget_usd=0.25))
        self.assertEqual([f.rule for f in findings], ["budget-blowout"])
        self.assertEqual(audit_session(s), [])  # no budgets configured


if __name__ == "__main__":
    unittest.main()
