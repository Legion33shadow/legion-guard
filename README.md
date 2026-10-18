# legion-guard — verify before connect

An agent reads an MCP server's tool descriptions as instructions. The server you approved last week can expose other
tools, or the same tools with other descriptions, today. `legion-guard` checks the `tools/list` **your client actually
receives**, at connect time.

```python
import legion_guard
session = legion_guard.wrap(session, "com.dexpaprika/dexpaprika")   # after session.initialize(); one line, no config file
tools = await session.list_tools()
print(session.report["verdict"])     # NO_CHANGE_DETECTED | CHANGE_DETECTED | UNVERIFIED
```

## Try it in about a minute (including the virtualenv + install)

```sh
python3 -m venv v && . v/bin/activate && pip install legion-guard
python -m legion_guard check https://mcp.dexpaprika.com/streamable-http com.dexpaprika/dexpaprika
```

It connects to the public DexPaprika MCP server (`initialize` + `tools/list`, no tool call), fingerprints the 20 tools it
receives and checks them against the latest list signed by the LEGION log. Look for `"state": "MATCHES_SIGNED"` (or
`DIFFERS_FROM_SIGNED`, `UNKNOWN`, `UNVERIFIED`); exit code 0 = no difference, 1 = difference, 2 = connection error.

## Low risk to add (tested)

- **Observes by default.** The default mode is `warn`: changes are logged (`logging.getLogger("legion_guard")`) and reported
  in `session.report`; no tool is hidden and no call is refused.
- **Never breaks your app.** If a source is unreachable or fails, it is reported `UNAVAILABLE` and nothing is blocked,
  in every mode. Internal errors of the guard are logged, never raised.
- **Blocking is opt-in.** `wrap(session, server_id, mode="block")` hides from `list_tools()` and refuses in `call_tool()`
  only the tools for which a source has evidence of a change (changed or new tool). `UNKNOWN` and `UNAVAILABLE` never block.

## Removable: LEGION is the default, not a lock-in

Sources are pluggable. Each one compares the received list with its own reference:

| Source | Reference | Network |
|---|---|---|
| `FirstUseSource()` (default) | the first list seen for this server, pinned in `~/.cache/legion-guard/pins.json` | none |
| `LegionSource()` (default when a registry id is given) | latest list signed by the LEGION transparency log: record + RFC 9162 inclusion proof + signed head, keys from a pinned root key | `tlog.legion-api.com` |
| `LegionSource(base=..., root_pin=...)` | the same check against another log that serves this API (for example a self-hosted mirror) | your log |
| `LegionSource(witnesses=[vkey, ...], min_witnesses=N)` | additionally requires the signed head to be a C2SP checkpoint signed by the log and cosigned by N of **your** witnesses | as above |
| `PinnedSource(dict_or_lockfile)` | fingerprints you pinned yourself (`mcp-tools-lock/0.1`, same format as legion-lock) | none |
| your own object with `.name` and `.check(server_id, fp)` | anything | yours |

```python
session = legion_guard.wrap(session, "io.example/server", sources=[legion_guard.PinnedSource(".mcp-tools.lock.json")])  # no LEGION at all
```

Measured on 2026-10-17: the 20-tool list served by `mcp.dexpaprika.com/streamable-http` matches the list LEGION signed
(`MATCHES`), also when the head must be a checkpoint cosigned by a chosen witness. There is no independent witness
of the LEGION log yet: the only cosigning witness today is run by LEGION itself.

## Limits

- LEGION observes only part of the servers; absence from the log is not a verdict (`UNKNOWN`).
- A change is not an attack. This does not certify that a server is secure, and says nothing about what the tools do.
- First-use pinning trusts the first list it sees.
- With `witnesses=`, the result is `UNAVAILABLE` (never blocking) until your witnesses have cosigned the log's current
  checkpoint. The only witness today is run by LEGION and cosigns hourly, so after each new head there is a window of up to
  about one hour where this option cannot confirm anything (measured on 2026-10-18).
- Fingerprints cover `name`, `description` and `inputSchema` (JCS RFC 8785), as in the LEGION log.
- Tested with the MCP Python SDK `ClientSession`; frameworks that build on it are not tested yet.

The 0.1 functions (`guard_session`, `evaluate`, `approve`, `python3 -m legion_guard check|approve`) are unchanged.
