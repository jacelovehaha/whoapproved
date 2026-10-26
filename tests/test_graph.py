import unittest
from pathlib import Path

from whoapproved.graph import build_sessions, delegation_chain
from whoapproved.ingest import load_jsonl

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class TestGraph(unittest.TestCase):
    def setUp(self):
        self.sessions = build_sessions(load_jsonl(EXAMPLES / "clean.jsonl"))
        self.s = self.sessions["clean-001"]

    def test_agents(self):
        self.assertEqual(set(self.s.agents), {"user", "lead", "researcher"})

    def test_roots_include_session_starter(self):
        self.assertIn("lead", self.s.roots)

    def test_delegation_chain(self):
        self.assertEqual(delegation_chain(self.s, "researcher"), ["lead", "researcher"])

    def test_usage_totals(self):
        self.assertEqual(self.s.total_tokens(), 15200)
        self.assertAlmostEqual(self.s.total_cost_usd(), 0.031)


if __name__ == "__main__":
    unittest.main()
