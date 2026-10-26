# whoapproved

**The flight recorder & approval auditor for multi-agent systems.**

When an AI agent does something consequential — writes a file, runs a shell
command, sends data out — one question decides whether it was work or an
incident:

> **Who approved this?**

`whoapproved` answers it from evidence. It ingests agent event traces,
rebuilds each session (including cross-agent delegation chains), and audits
them for the failures that keep showing up in production agent systems:
sensitive actions with **no human approval**, approvals **laundered** onto
tools they never covered, agents acting with **no recorded delegation**,
private data read and then **sent out**, and runaway tool loops.

Zero dependencies. Python ≥ 3.10. Built for CI: findings at or above a
severity you choose fail the build.

## Why now

Agents went multi-agent in 2026: MCP became the default tool protocol, A2A
the default agent-to-agent one, and orchestration replaced single-agent
deployments. But the infrastructure *between* agents — identity,
delegation, audit — is the part everyone agrees is underbuilt
([Beacon VC: "From Smarter Agents to Trusted Agents"](https://www.beaconvc.fund/knowledge/from-smarter-agents-to-trusted-agents-where-the-next-wave-of-ai-infrastructure-is-emerging/)).
Gartner formalized "Guardian Agents" as a category in 2026; the OWASP MCP
Top 10 documents tool poisoning, rug pulls and scope abuse in the wild
([MCP security risks, 2026](http://dev.to/ricco020/mcp-security-the-risks-of-model-context-protocol-and-how-to-govern-it-2026-1963)).

Models and frameworks have plenty of tooling. **The audit trail doesn't.**
That gap is what this project works on.

## Quickstart

```bash
pip install -e .          # or just PYTHONPATH=src python -m whoapproved

whoapproved audit examples/clean.jsonl      # 0 findings, exit 0
whoapproved audit examples/incident.jsonl   # 5 findings, exit 1
whoapproved timeline examples/clean.jsonl   # reconstructed session timeline
whoapproved audit examples/mcp_log.jsonl --mcp   # audit raw MCP JSON-RPC logs
whoapproved audit trace.jsonl --format json --out report.json
whoapproved audit trace.jsonl --budget-tokens 500000 --budget-usd 2.00
```

## What it catches

Anatomy of `examples/incident.jsonl` — a sub-agent hijacked by an indirect
prompt injection hidden in a web page:

```text
**5 finding(s)** across 1 session(s) (1 critical, 2 high).

[CRITICAL] exfiltration-path
  Private data read ('fs.read', class=secret) by 'browser' is followed by
  egress call 'http.post' by 'browser' in the same session.

[HIGH] unapproved-sensitive-action   (http.post — no approval anywhere)
[HIGH] unapproved-sensitive-action   (shell.exec by an un-delegated 'shadow')
[MEDIUM] runaway-loop                (http.get called 5× with identical args)
[MEDIUM] orphan-delegation           ('shadow' acts; no delegation recorded)
```

## Audit rules

| rule | severity | what it means |
|---|---|---|
| `exfiltration-path` | critical | A `private`/`secret` read is followed by an egress call (send/post/upload/…) in the same session — the "lethal trifecta" as a trace query. |
| `unapproved-sensitive-action` | high | A sensitive tool (exec/write/delete/send/pay/…) runs with **no prior** human approval in the session. Approvals that arrive afterwards don't count. |
| `approval-scope-mismatch` | high | Approvals exist, but none covers this tool — consent was laundered onto an action nobody approved. Scopes support `*` and `fnmatch` patterns (e.g. `fs.*`). |
| `orphan-delegation` | medium | An agent performs tool calls but is neither a session root nor the target of any recorded delegation — a broken chain of authority. |
| `runaway-loop` | medium | Same tool + identical arguments ≥ 5 times (configurable) in one session. |
| `budget-blowout` | medium | Session token/cost totals exceed `--budget-tokens` / `--budget-usd`. |

Tool sensitivity, egress and data classification are heuristic by design
(name patterns + argument markers such as `.ssh`, `.env`, `id_rsa`, plus an
explicit `data_class` field when your framework provides one). They are
meant to be tuned, not trusted blindly.

## Trace format

A trace is JSONL. Every event has `ts`, `session`, `agent`, `type`:

```json
{"ts": "2026-10-27T09:00:02Z", "session": "s1", "agent": "user", "type": "human_approval", "approved_by": "kevin", "scope": ["fs.write"]}
{"ts": "2026-10-27T09:00:03Z", "session": "s1", "agent": "lead", "type": "delegation", "to_agent": "researcher", "task": "Collect supplier pages"}
{"ts": "2026-10-27T09:00:07Z", "session": "s1", "agent": "lead", "type": "tool_call", "tool": "fs.write", "args": {"path": "workspace/summary.md"}, "data_class": "internal"}
```

Event types: `session_start`, `session_end`, `delegation`, `tool_call`,
`tool_result`, `human_approval`, `message`, `usage`, `error`.
Data classes: `public`, `internal`, `private`, `secret`.

**MCP logs**: with `--mcp`, `tools/call` JSON-RPC records map to tool calls
automatically, so traffic logged by an MCP host or proxy can be audited
directly (see `examples/mcp_log.jsonl`).

## Reports

- **Markdown** (default): session table, findings sorted by severity, and a
  per-session timeline reconstructed from the raw events.
- **JSON** (`--format json`): sessions, delegation chains, token/cost
  totals, findings with evidence — ready for dashboards and SIEM ingestion.
- **Exit codes**: `0` clean · `1` findings at/above `--fail-on`
  (default `high`) · `2` input error.

## Roadmap

- A2A (Agent2Agent) task-log adapter
- OpenTelemetry trace import
- Signed approval receipts (JWS) so approvals are verifiable, not just logged
- A recording MCP proxy that produces whoapproved traces live
- Framework emitters (LangGraph, CrewAI, AutoGen)

## Contributing

Issues and PRs welcome — especially new adapters and new audit rules.
Keep it zero-dependency; the standard library is a feature.

## License

MIT
