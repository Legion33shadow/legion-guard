#!/usr/bin/env python3
"""legion-guard 0.2.3 : changement de tools/list EN COURS de session (SDK MCP officiel + faux serveur stdio). Code 0 = tout OK."""
import asyncio, os, sys, tempfile, logging
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(H))
os.environ["HOME"] = tempfile.mkdtemp()                      # le garde n'écrit jamais dans le vrai ~/.cache
import legion_guard as G
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
logging.basicConfig(level=logging.ERROR)
R = []
def ck(n, c, d=""): R.append(bool(c)); print(("OK   " if c else "ÉCHEC"), n, "" if c else "| " + str(d)[:300])

async def run(mode):
    p = StdioServerParameters(command=sys.executable, args=[os.path.join(H, "fake_midsession_server.py")])
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            reports = []
            gs = G.wrap(s, "test.example/midsession", sources=[G.FirstUseSource(os.path.join(tempfile.mkdtemp(), "p.json"))], mode=mode, on_report=reports.append)
            first = [t.name for t in (await gs.list_tools()).tools]
            same = [t.name for t in (await gs.list_tools()).tools]          # liste inchangée : aucun changement signalé
            v_same = gs.report["verdict"]
            for _ in range(3):
                await gs.call_tool("format_text", {"text": " x "})
            seen = [t.name for t in (await gs.list_tools()).tools]
            wire = [t.description for t in (await s.list_tools()).tools]
            try:
                await gs.call_tool("format_text", {"text": "x"}); call = "called"
            except G.ToolNotApproved:
                call = "refused"
            return dict(first=first, same=same, v_same=v_same, seen=seen, wire=wire, call=call, rep=gs.report, n_reports=len(reports))

async def main():
    o = await run("warn")
    ck("liste relue inchangée : pas de changement signalé", o["same"] == o["first"] and o["v_same"] != "CHANGE_DETECTED", o["v_same"])
    ck("warn : changement en cours de session détecté", o["rep"]["verdict"] == "CHANGE_DETECTED" and o["rep"]["mid_session_changed_tools"] == ["format_text"], o["rep"])
    ck("warn : rien retiré ni refusé", o["seen"] == ["format_text"] and o["call"] == "called", (o["seen"], o["call"]))
    ck("warn : rapport transmis à on_report", o["n_reports"] == 2, o["n_reports"])
    o = await run("block")
    ck("le serveur a bien changé sa description sur le fil", "TEST ONLY" in o["wire"][0], o["wire"])
    ck("block : l'outil modifié est retiré de list_tools()", o["seen"] == [] and o["rep"]["hidden_tools"] == ["format_text"], (o["seen"], o["rep"].get("hidden_tools")))
    ck("block : appel de l'outil modifié refusé", o["call"] == "refused", o["call"])
asyncio.run(main())
print("%d/%d" % (sum(R), len(R))); sys.exit(0 if all(R) else 1)
