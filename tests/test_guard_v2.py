#!/usr/bin/env python3
"""legion-guard 0.2 : tests de bout en bout (SDK MCP officiel + faux serveur stdio + journal LEGION réel). Code 0 = tout OK."""
import asyncio, os, socket, sys, tempfile, logging
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(H))
REAL_HOME = os.environ.get("HOME", "")
os.environ["HOME"] = tempfile.mkdtemp()                      # le garde n'écrit jamais dans le vrai ~/.cache
import legion_guard as G
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
logging.basicConfig(level=logging.ERROR)
R = []
def ck(n, c, d=""): R.append(bool(c)); print(("OK   " if c else "ÉCHEC"), n, "" if c else "| " + str(d)[:300])
DOWN = G.LegionSource(base="http://127.0.0.1:9/tlog/v1", timeout=2)
PINS = os.path.join(tempfile.mkdtemp(), "pins.json")

async def run(variant, fn):
    p = StdioServerParameters(command=sys.executable, args=[os.path.join(H, "fake_server.py")], env={**os.environ, "HOME": REAL_HOME, "FAKE_VARIANT": variant})
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return await fn(s)

def scenario(server_id, sources, mode="warn", calls=("add", "lookup", "exfil")):
    async def fn(s):
        gs = G.wrap(s, server_id, sources=sources, mode=mode) if sources is not None else G.wrap(s)
        names = sorted(t.name for t in (await gs.list_tools()).tools)
        out = {}
        for n in calls:
            try:
                await gs.call_tool(n, {"add": {"a": 1, "b": 2}, "lookup": {"city": "Paris"}, "exfil": {"path": "x"}}[n]); out[n] = "called"
            except G.ToolNotApproved:
                out[n] = "refused"
            except Exception as e:
                out[n] = "err:" + type(e).__name__
        return gs.report, names, out
    return fn

async def main():
    fu = G.FirstUseSource(PINS)
    rep, names, calls = await run("v1", scenario("test.example/fake", [fu, DOWN], calls=("add", "lookup")))
    ck("fail-open : LEGION injoignable -> UNAVAILABLE, rien n'est bloqué", rep["sources"]["legion"]["state"] == "UNAVAILABLE" and names == ["add", "lookup"] and calls == {"add": "called", "lookup": "called"}, (rep, names, calls))
    ck("1re connexion : épinglée localement (PINNED_NOW), verdict UNVERIFIED", rep["sources"]["first-use"]["state"] == "PINNED_NOW" and rep["verdict"] == "UNVERIFIED", rep)
    rep, names, calls = await run("v2", scenario("test.example/fake", [fu, DOWN]))
    ck("warn (défaut) : changement détecté (lookup modifié, exfil nouveau)", rep["verdict"] == "CHANGE_DETECTED" and rep["changed_tools"] == ["exfil", "lookup"], rep)
    ck("warn (défaut) : rien n'est retiré ni refusé", names == ["add", "exfil", "lookup"] and set(calls.values()) == {"called"}, (names, calls))
    rep, names, calls = await run("v2", scenario("test.example/fake", [fu, DOWN], mode="block"))
    ck("block (opt-in) : seuls les outils changés sont retirés", names == ["add"] and rep["hidden_tools"] == ["exfil", "lookup"], (names, rep))
    ck("block (opt-in) : appels des outils changés refusés, l'outil inchangé reste appelable", calls == {"add": "called", "lookup": "refused", "exfil": "refused"}, calls)
    rep, names, calls = await run("v2", scenario("test.example/fake", [DOWN], mode="block"))
    ck("block + seule source injoignable : rien n'est bloqué (aucune preuve de changement)", names == ["add", "exfil", "lookup"] and rep["verdict"] == "UNVERIFIED", (names, rep))
    # source épinglée alternative, sans aucun réseau (connect interdit)
    fp1 = await run("v1", lambda s: _fp(s))
    real_connect = socket.socket.connect
    socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("réseau interdit"))
    try:
        rep, names, calls = await run("v2", scenario("test.example/fake", [G.PinnedSource({"test.example/fake": fp1})], mode="block"))
        ck("PinnedSource seule, hors ligne : changement détecté et bloqué (opt-in)", names == ["add"] and rep["sources"]["pinned"]["state"] == "DIFFERS", (names, rep))
        rep, names, _ = await run("v1", scenario("test.example/fake", [G.PinnedSource({"test.example/fake": fp1})], calls=()))
        ck("PinnedSource seule, hors ligne : liste identique -> NO_CHANGE_DETECTED", rep["verdict"] == "NO_CHANGE_DETECTED", rep)
    finally:
        socket.socket.connect = real_connect
    class Broken:
        name = "broken"
        def check(self, sid, fp): raise RuntimeError("boom")
    rep, names, calls = await run("v2", scenario("test.example/fake", [Broken()], mode="block"))
    ck("source cassée : avalée (UNAVAILABLE), l'application continue", rep["sources"]["broken"]["state"] == "UNAVAILABLE" and names == ["add", "exfil", "lookup"], (rep, names))
    zfu = G.FirstUseSource(os.path.join(tempfile.mkdtemp(), "z.json"))
    await run("v1", lambda s: _zero(s, zfu))
    rep, names, calls = await run("v2", lambda s: _zero(s, zfu, calls=True))
    ck("zéro config sur un serveur qui change : défaut = observe, rien retiré ni refusé", rep["verdict"] == "CHANGE_DETECTED" and names == ["add", "exfil", "lookup"] and set(calls.values()) == {"called"}, (rep, names, calls))
    rep, names, calls = await run("v1", scenario(None, None, calls=("add",)))
    ck("zéro config : wrap(session) fonctionne, épingle au 1er usage", names == ["add", "lookup"] and calls == {"add": "called"} and rep["sources"]["first-use"]["state"] == "PINNED_NOW", (rep, names))

async def _zero(s, src, calls=False):
    gs = G.wrap(s, "test.example/zero")            # aucun mode donné : le défaut est testé ici
    gs.sources = [src]                               # même défaut, fichier d'épinglage isolé
    names = sorted(t.name for t in (await gs.list_tools()).tools); out = {}
    if calls:
        for n, a in (("add", {"a": 1, "b": 2}), ("lookup", {"city": "x"}), ("exfil", {"path": "x"})):
            try:
                await gs.call_tool(n, a); out[n] = "called"
            except G.ToolNotApproved:
                out[n] = "refused"
    return gs.report, names, out


async def _fp(s):
    fp = G.fingerprint((await s.list_tools()).tools); return {"tools_sha256": fp["sha256"], "tools": fp["per_tool"]}

async def real():
    from mcp.client.streamable_http import streamable_http_client
    async def go(sources):
        async with streamable_http_client("https://mcp.dexpaprika.com/streamable-http") as (r, w, *_):
            async with ClientSession(r, w) as s:
                await s.initialize(); gs = G.wrap(s, "com.dexpaprika/dexpaprika", sources=sources)
                await gs.list_tools(); return gs.report
    rep = await go([G.LegionSource()])
    ck("LEGION réel : dexpaprika MATCHES (preuve vérifiée)", rep["sources"]["legion"]["state"] == "MATCHES", rep["sources"])
    self_w = "legion-self.legion-api.com+77087322+BLq1y12s/OT49hdkWonJHA1h7xuus8QS0UDb7mFQpVgB"
    rep = await go([G.LegionSource(witnesses=[self_w], min_witnesses=1)])
    st = rep["sources"]["legion"]
    ck("option C2SP : checkpoint cosigné par le témoin choisi -> MATCHES + witnessed_by (ou UNAVAILABLE si tête en cours, jamais bloquant)",
       (st["state"] == "MATCHES" and st.get("witnessed_by") == ["legion-self.legion-api.com"]) or (st["state"] == "UNAVAILABLE" and ("differ" in st.get("reason", "") or "not cosigned" in st.get("reason", ""))), st)
    other = "someone.example+00000000+BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    rep = await go([G.LegionSource(witnesses=[other], min_witnesses=1)])
    ck("option C2SP : témoin absent -> UNAVAILABLE (non bloquant)", rep["sources"]["legion"]["state"] == "UNAVAILABLE", rep["sources"])

asyncio.run(main())
if "--offline" not in sys.argv:
    asyncio.run(real())
print("%d/%d" % (sum(R), len(R))); sys.exit(0 if all(R) else 1)
