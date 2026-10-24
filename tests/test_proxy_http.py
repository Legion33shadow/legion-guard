#!/usr/bin/env python3
"""Proxy legion-guard --url : SDK MCP officiel (client stdio) -> python3 -m legion_guard proxy --url -> faux serveur streamable HTTP
local (127.0.0.1). Aucun réseau externe (--no-legion) ; cache temporaire. Code 0 = tout OK."""
import asyncio, json, os, socket, subprocess, sys, tempfile, time, logging
H = os.path.dirname(os.path.abspath(__file__)); SRC = os.path.dirname(H)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
logging.basicConfig(level=logging.CRITICAL)
R = []
def ck(n, c, d=""): R.append(bool(c)); print(("OK   " if c else "ÉCHEC"), n, "" if c else "| " + str(d)[:400])
ENV = dict(os.environ, PYTHONPATH=SRC)


def server(variant):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    p = subprocess.Popen([sys.executable, os.path.join(H, "fake_annot_server.py")], env=dict(ENV, FAKE_VARIANT=variant, FAKE_PORT=str(port)),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError:
            time.sleep(0.1)
    return p, "http://127.0.0.1:%d/mcp" % port


async def call(s, name, args):
    try:
        r = await s.call_tool(name, args)
        return "error" if getattr(r, "is_error", getattr(r, "isError", False)) else "ok"
    except Exception as e:
        return "refused:" + str(getattr(getattr(e, "error", None), "code", type(e).__name__))


async def use(s, n_calls):
    await s.initialize()
    l1 = (await s.list_tools()).tools
    for _ in range(n_calls):
        await s.call_tool("format_text", {"text": " x "})
    l2 = (await s.list_tools()).tools if n_calls else l1
    return dict(l1=l1, l2=l2, fmt=await call(s, "format_text", {"text": "x"}), dele=await call(s, "delete_file", {"path": "/nonexistent"}))


async def via_proxy(url, cache, mode, n_calls=0):
    p = StdioServerParameters(command=sys.executable, args=["-m", "legion_guard", "proxy", "--url", url, "--no-legion", "--mode", mode, "--cache", cache], env=ENV)
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            return await use(s, n_calls)


async def direct(url):
    async with streamable_http_client(url) as (r, w, *_):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return (await s.list_tools()).tools


def audit(cache):
    """Événements tools/list seulement (les refus d'appel sont journalisés à part)."""
    p = os.path.join(cache, "proxy-audit.jsonl")
    return [x for x in (json.loads(l) for l in open(p)) if x["event"].startswith("tools/list")] if os.path.exists(p) else []


def names(ts):
    return [t.name for t in ts]


async def main():
    srv, url = server("base")
    try:
        c = tempfile.mkdtemp()
        d = await direct(url)
        o = await via_proxy(url, c, "warn")
        ck("HTTP transparent : tools/list via proxy = direct", [t.model_dump(by_alias=True, exclude_none=True) for t in o["l1"]] ==
           [t.model_dump(by_alias=True, exclude_none=True) for t in d])
        ck("HTTP : appels transmis au serveur distant", o["fmt"] == "ok" and o["dele"] == "ok", o)
        a = audit(c)
        ck("HTTP : référence posée sous l'identifiant url:…", a and a[-1]["server_id"] == "url:" + url and a[-1]["hints"]["state"] == "PINNED_NOW", a[-1:])
        o = await via_proxy(url, c, "block", n_calls=2)          # 1 + 2 appels : le serveur change format_text au 3e
        a = audit(c)
        ck("HTTP block : changement en cours de session retiré et refusé (-32001)",
           names(o["l2"]) == ["delete_file", "fetch_url"] and o["fmt"] == "refused:-32001" and a[-1].get("mid_session_changed_tools") == ["format_text"],
           (names(o["l2"]), o["fmt"], a[-1].get("mid_session_changed_tools")))
    finally:
        srv.terminate(); srv.wait()
    srv, url2 = server("relaxed")
    try:
        c2 = tempfile.mkdtemp()
        srv0, _ = None, None
        # même identifiant pour les deux serveurs : --server-id local, sans LEGION
        async def vp(u, mode):
            p = StdioServerParameters(command=sys.executable, args=["-m", "legion_guard", "proxy", "--url", u, "--server-id", "test.example/annot",
                                      "--no-legion", "--mode", mode, "--cache", c2], env=ENV)
            async with stdio_client(p) as (r, w):
                async with ClientSession(r, w) as s:
                    return await use(s, 0)
        b, ub = server("base")
        try:
            await vp(ub, "block")
        finally:
            b.terminate(); b.wait()
        o = await vp(url2, "block")
        a = audit(c2)
        ck("HTTP : annotations relâchées détectées, delete_file retiré et refusé",
           {(x["tool"], x["hint"]) for x in a[-1]["hint_changes"] if x["relaxed"]} == {("delete_file", "readOnlyHint"), ("delete_file", "destructiveHint")}
           and "delete_file" not in names(o["l1"]) and o["dele"] == "refused:-32001", (a[-1]["hint_changes"], names(o["l1"]), o["dele"]))
    finally:
        srv.terminate(); srv.wait()
    r = subprocess.run([sys.executable, "-m", "legion_guard", "proxy", "--url", "http://127.0.0.1:9/mcp", "--no-legion", "--cache", tempfile.mkdtemp()],
                       input=b"", capture_output=True, env=ENV, timeout=60)
    ck("HTTP injoignable : le proxy s'arrête sans planter (pas de trace)", b"Traceback" not in r.stderr, r.stderr[-300:])
    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["x"]}, "remote": {"type": "http", "url": "https://example.invalid/mcp"},
                          "authed": {"type": "http", "url": "https://example.invalid/a", "headers": {"Authorization": "Bearer X"}},
                          "old": {"type": "sse", "url": "https://example.invalid/sse"}}}
    p = os.path.join(tempfile.mkdtemp(), "c.json"); json.dump(cfg, open(p, "w"))
    w0 = json.loads(subprocess.run([sys.executable, "-m", "legion_guard", "wrap-config", p], capture_output=True, text=True, env=ENV).stdout)
    w = json.loads(subprocess.run([sys.executable, "-m", "legion_guard", "wrap-config", p, "--http"], capture_output=True, text=True, env=ENV).stdout)
    ck("wrap-config sans --http : HTTP intact (comportement 0.2.6)", w0["mcpServers"]["remote"] == cfg["mcpServers"]["remote"])
    ck("wrap-config --http : HTTP sans en-têtes enveloppé ; avec en-têtes et SSE intacts",
       w["mcpServers"]["remote"]["args"][-2:] == ["--url", "https://example.invalid/mcp"] and w["mcpServers"]["authed"] == cfg["mcpServers"]["authed"]
       and w["mcpServers"]["old"] == cfg["mcpServers"]["old"] and w["mcpServers"]["fs"]["args"][-2:] == ["npx", "x"], w)
    json.dump(w, open(p, "w"))
    w2 = json.loads(subprocess.run([sys.executable, "-m", "legion_guard", "wrap-config", p, "--http"], capture_output=True, text=True, env=ENV).stdout)
    ck("wrap-config --http : idempotent", w2 == w)

asyncio.run(main())
print("%d/%d" % (sum(R), len(R))); sys.exit(0 if all(R) else 1)
