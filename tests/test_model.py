import unittest

from whoapproved.model import (
    infer_data_class,
    is_egress_tool,
    is_sensitive_tool,
    parse_event,
)


class TestParseEvent(unittest.TestCase):
    def test_minimal_ok(self):
        e = parse_event({"ts": "t", "session": "s", "agent": "a", "type": "message"}, 0)
        self.assertEqual(e.agent, "a")

    def test_missing_field_raises(self):
        with self.assertRaises(ValueError):
            parse_event({"ts": "t", "session": "s", "type": "message"}, 0)

    def test_unknown_type_raises(self):
        with self.assertRaises(ValueError):
            parse_event({"ts": "t", "session": "s", "agent": "a", "type": "nope"}, 0)

    def test_bad_data_class_raises(self):
        with self.assertRaises(ValueError):
            parse_event({"ts": "t", "session": "s", "agent": "a", "type": "tool_call",
                         "tool": "fs.read", "data_class": "topsecret"}, 0)


class TestClassifiers(unittest.TestCase):
    def test_sensitive(self):
        self.assertTrue(is_sensitive_tool("shell.exec"))
        self.assertTrue(is_sensitive_tool("fs.write"))
        self.assertTrue(is_sensitive_tool("payments.transfer"))
        self.assertFalse(is_sensitive_tool("fs.read"))
        self.assertFalse(is_sensitive_tool("http.get"))
        self.assertFalse(is_sensitive_tool(None))

    def test_egress(self):
        self.assertTrue(is_egress_tool("http.post"))
        self.assertTrue(is_egress_tool("email.send"))
        self.assertFalse(is_egress_tool("http.get"))

    def test_infer_secret_from_args(self):
        e = parse_event({"ts": "t", "session": "s", "agent": "a", "type": "tool_call",
                         "tool": "fs.read", "args": {"path": "~/.ssh/id_rsa"}}, 0)
        self.assertEqual(infer_data_class(e), "secret")

    def test_explicit_class_wins(self):
        e = parse_event({"ts": "t", "session": "s", "agent": "a", "type": "tool_call",
                         "tool": "fs.read", "args": {"path": "~/.ssh/id_rsa"},
                         "data_class": "internal"}, 0)
        self.assertEqual(infer_data_class(e), "internal")


if __name__ == "__main__":
    unittest.main()
