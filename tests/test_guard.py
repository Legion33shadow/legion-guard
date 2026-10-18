#!/usr/bin/env python3
"""Tests de bout en bout de legion-guard avec un vrai client MCP (SDK officiel) et un faux serveur stdio. Code 0 = tout OK."""
import asyncio, os, sys, tempfile
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(H))
import legion_guard as G
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
R = []
def ck(n, c, d=""): R.append(bool(c)); print(("OK   " if c else "ÉCHEC"), n, "" if c else "| " + str(d)[:300])
LOCK = os.path.join(tempfile.mkdtemp(), "lock.json")

async def run(variant, mode, fn):
    p = StdioServerParameters(command=sys.executable, args=[os.path.join(H, "fake_server.py")], env={**os.environ, "FAKE_VARIANT": variant})
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return await fn(s, mode)

async def approve(s, mode):
    G.approve("test.example/fake", (await s.list_tools()).tools, LOCK); return None

async def guarded(s, mode):
    rep = await G.guard_session(s, "test.example/fake", LOCK, mode=mode, use_legion=False)
    names = sorted(t.name for t in (await s.list_tools()).tools)
    calls = {}
    for n, args in (("add", {"a": 2, "b": 3}), ("lookup", {"city": "Paris"}), ("exfil", {"path": "/etc/passwd"})):
        try:
            r = await s.call_tool(n, args); calls[n] = "called"
        except G.ToolNotApproved:
            calls[n] = "refused"
        except Exception as e:
            calls[n] = "error:" + type(e).__name__
    return rep, names, calls

async def main():
    await run("v1", None, approve)
    rep, names, calls = await run("v1", "block", guarded)
    ck("v1 approuvé : MATCHES_APPROVED", rep["approval"] == "MATCHES_APPROVED", rep)
    ck("v1 block : les 2 outils exposés et appelables", names == ["add", "lookup"] and calls["add"] == calls["lookup"] == "called", (names, calls))
    rep, names, calls = await run("v2", "warn", guarded)
    ck("v2 warn : écart détecté (DIFFERS_FROM_APPROVED)", rep["approval"] == "DIFFERS_FROM_APPROVED", rep)
    ck("v2 warn : lookup CHANGED, exfil NEW, add APPROVED", rep["tools"] == {"add": "APPROVED", "lookup": "CHANGED", "exfil": "NEW"}, rep["tools"])
    ck("v2 warn : rien de bloqué (rapport seulement)", calls["lookup"] == "called" and names == ["add", "exfil", "lookup"], (names, calls))
    rep, names, calls = await run("v2", "block", guarded)
    ck("v2 block : seul l'outil approuvé et inchangé est exposé", names == ["add"], names)
    ck("v2 block : appel de l'outil modifié REFUSÉ", calls["lookup"] == "refused", calls)
    ck("v2 block : appel du nouvel outil REFUSÉ", calls["exfil"] == "refused", calls)
    ck("v2 block : l'outil approuvé reste appelable", calls["add"] == "called", calls)
    rep = G.evaluate("test.example/fake", [{"name": "add", "description": "Add two numbers.", "inputSchema": {}}], os.path.join(tempfile.mkdtemp(), "none.json"), use_legion=False)
    ck("sans lockfile : NO_APPROVAL / NOT_APPROVED", rep["approval"] == "NO_APPROVAL" and rep["tools"]["add"] == "NOT_APPROVED", rep)
    ck("claim boundary présente", "not an attack" in rep["claim_boundary"] and "not certify" in rep["claim_boundary"])
asyncio.run(main())
print("%d/%d" % (sum(R), len(R))); sys.exit(0 if all(R) else 1)
