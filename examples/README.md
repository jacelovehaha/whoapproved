# Example traces

## clean.jsonl — a well-governed session (expect: 0 findings)

A user asks the `lead` agent to research suppliers. The user approves
`fs.write` up front, `lead` delegates browsing to `researcher`, and the only
sensitive call (writing the summary) is covered by that approval.

```bash
whoapproved audit examples/clean.jsonl
# exit code 0
```

## incident.jsonl — an injected sub-agent (expect: 5 findings)

A supplier web page carries an indirect prompt injection. The `browser`
sub-agent loops on the same page (5 identical calls), reads an SSH private
key, and POSTs data to an external collector — with **no human approval
anywhere in the session**. An un-delegated `shadow` agent also appears and
runs a shell command.

```bash
whoapproved audit examples/incident.jsonl
# [CRITICAL] exfiltration-path
# [HIGH]     unapproved-sensitive-action  (http.post)
# [HIGH]     unapproved-sensitive-action  (shell.exec)
# [MEDIUM]   runaway-loop                 (http.get x5)
# [MEDIUM]   orphan-delegation            (shadow)
# exit code 1
```

## mcp_log.jsonl — raw MCP JSON-RPC traffic

```bash
whoapproved audit examples/mcp_log.jsonl --mcp
```
