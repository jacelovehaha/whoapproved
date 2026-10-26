import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from whoapproved.cli import main
from whoapproved.ingest import adapt_mcp_record, load_mcp_log

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class TestMcpAdapter(unittest.TestCase):
    def test_tools_call_maps_to_tool_call(self):
        e = adapt_mcp_record({"method": "tools/call",
                              "params": {"name": "fs.read", "arguments": {"path": "x"}}}, 0)
        self.assertEqual(e.type, "tool_call")
        self.assertEqual(e.tool, "fs.read")

    def test_result_maps_to_tool_result(self):
        e = adapt_mcp_record({"result": {}, "id": 1}, 0)
        self.assertEqual(e.type, "tool_result")

    def test_other_method_ignored(self):
        self.assertIsNone(adapt_mcp_record({"method": "resources/list"}, 0))

    def test_load_example(self):
        events = load_mcp_log(EXAMPLES / "mcp_log.jsonl")
        self.assertEqual([e.type for e in events], ["tool_call", "tool_result", "tool_call"])


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_audit_clean_exits_0(self):
        code, out = self.run_cli(["audit", str(EXAMPLES / "clean.jsonl")])
        self.assertEqual(code, 0)
        self.assertIn("0 finding(s)", out)

    def test_audit_incident_exits_1(self):
        code, out = self.run_cli(["audit", str(EXAMPLES / "incident.jsonl")])
        self.assertEqual(code, 1)
        self.assertIn("exfiltration-path", out)

    def test_audit_json_format(self):
        code, out = self.run_cli(["audit", str(EXAMPLES / "incident.jsonl"),
                                  "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["total_findings"], 5)

    def test_timeline(self):
        code, out = self.run_cli(["timeline", str(EXAMPLES / "clean.jsonl")])
        self.assertEqual(code, 0)
        self.assertIn("researcher", out)


if __name__ == "__main__":
    unittest.main()
