#!/usr/bin/env python3
"""Proxy stdio legion-guard : SDK MCP officiel (client) -> python3 -m legion_guard proxy -> faux serveur stdio. Code 0 = tout OK.
Aucun réseau (--no-legion) ; cache dans un dossier temporaire."""
import asyncio, json, os, subprocess, sys, tempfile, logging
H = os.path.dirname(os.path.abspath(__file__)); SRC = os.path.dirname(H)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
logging.basicConfig(level=logging.CRITICAL)
R = []
def ck(n, c, d=""): R.append(bool(c)); print(("OK   " if c else "ÉCHEC"), n, "" if c else "| " + str(d)[:400])
FAKE = [sys.executable, os.path.join(H, "fake_annot_server.py")]


def params(cache, mode, variant, proxied=True):
    env = dict(os.environ, PYTHONPATH=SRC, FAKE_VARIANT=variant)
    if not proxied:
        return StdioServerParameters(command=FAKE[0], args=FAKE[1:], env=env)
    return StdioServerParameters(command=sys.executable, args=["-m", "legion_guard", "proxy", "--no-legion", "--mode", mode,
                                 "--cache", cache, "--"] + FAKE, env=env)


async def call(s, name, args):
    try:
        r = await s.call_tool(name, args)
        return "error" if getattr(r, "is_error", getattr(r, "isError", False)) else "ok"
    except Exception as e:
        return "refused:" + str(getattr(getattr(e, "error", None), "code", type(e).__name__))


async def session(cache, mode, variant, n_calls=0, proxied=True):
    async with stdio_client(params(cache, mode, variant, proxied)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            l1 = (await s.list_tools()).tools
            for _ in range(n_calls):
                await s.call_tool("format_text", {"text": " x "})
            l2 = (await s.list_tools()).tools if n_calls else l1
            return dict(l1=l1, l2=l2, fmt=await call(s, "format_text", {"text": "x"}),
                        dele=await call(s, "delete_file", {"path": "/nonexistent"}))


def audit(cache):
    p = os.path.join(cache, "proxy-audit.jsonl")
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


def dump(tools):
    return [t.model_dump(by_alias=True, exclude_none=True) for t in tools]


async def main():
    c = tempfile.mkdtemp()
    direct = await session(tempfile.mkdtemp(), "warn", "base", proxied=False)
    o = await session(c, "warn", "base")
    ck("transparent : tools/list via proxy = tools/list direct", dump(o["l1"]) == dump(direct["l1"]))
    ck("1re connexion : appels transmis", o["fmt"] == "ok" and o["dele"] == "ok", o)
    a = audit(c)
    ck("1re connexion : référence locale posée, aucun changement", a and a[-1]["verdict"] == "UNVERIFIED" and a[-1]["hints"]["state"] == "PINNED_NOW", a[-1:])

    o = await session(c, "warn", "base", n_calls=3)
    a = audit(c)
    ck("warn : changement de description en cours de session détecté",
       a[-1]["verdict"] == "CHANGE_DETECTED" and a[-1].get("mid_session_changed_tools") == ["format_text"], a[-1])
    ck("warn : rien retiré, rien refusé", len(o["l2"]) == 3 and o["fmt"] == "ok", (len(o["l2"]), o["fmt"]))

    c2 = tempfile.mkdtemp(); await session(c2, "block", "base")
    o = await session(c2, "block", "base", n_calls=3)
    ck("block : outil modifié en cours de session retiré de tools/list", [t.name for t in o["l2"]] == ["delete_file", "fetch_url"], [t.name for t in o["l2"]])
    ck("block : son appel reçoit l'erreur JSON-RPC -32001 sans atteindre le serveur", o["fmt"] == "refused:-32001", o["fmt"])

    o = await session(c2, "warn", "relaxed")
    a = audit(c2)
    hc = a[-1]["hint_changes"]
    ck("annotations relâchées détectées (delete_file : readOnly faux->vrai, destructive vrai->faux)",
       {(x["hint"], x["before"], x["after"], x["relaxed"]) for x in hc if x["tool"] == "delete_file"} ==
       {("readOnlyHint", False, True, True), ("destructiveHint", True, False, True)}, hc)
    ck("relâchement = CHANGE_DETECTED alors que l'empreinte est identique", a[-1]["verdict"] == "CHANGE_DETECTED" and not a[-1]["changed_tools"], a[-1])
    ck("warn : delete_file reste visible et appelable", "delete_file" in [t.name for t in o["l1"]] and o["dele"] == "ok", o["dele"])

    o = await session(c2, "block", "relaxed")
    ck("block : delete_file (annotation relâchée) retiré et refusé",
       "delete_file" not in [t.name for t in o["l1"]] and o["dele"] == "refused:-32001", ([t.name for t in o["l1"]], o["dele"]))
    ck("block : les autres outils passent", o["fmt"] == "ok", o["fmt"])

    c3 = tempfile.mkdtemp(); await session(c3, "block", "base")
    o = await session(c3, "block", "stricter")
    a = audit(c3)
    ck("annotation plus prudente : signalée, non relâchée, non bloquante",
       a[-1]["hint_changes"] == [{"tool": "fetch_url", "hint": "readOnlyHint", "before": True, "after": False, "relaxed": False}]
       and "fetch_url" in [t.name for t in o["l1"]], a[-1]["hint_changes"])

    ro = tempfile.mkdtemp(); os.chmod(ro, 0o500)
    o = await session(os.path.join(ro, "x"), "block", "base")
    ck("fail-open : cache non inscriptible -> trafic transmis", len(o["l1"]) == 3 and o["fmt"] == "ok", (len(o["l1"]), o["fmt"]))
    os.chmod(ro, 0o700)

    cfg = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
                          "remote": {"type": "http", "url": "https://example.invalid/mcp"}}}
    p = os.path.join(tempfile.mkdtemp(), "c.json"); json.dump(cfg, open(p, "w"))
    r = subprocess.run([sys.executable, "-m", "legion_guard", "wrap-config", p], capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC))
    w = json.loads(r.stdout)
    ck("wrap-config : serveur stdio enveloppé, HTTP intact, fichier source inchangé",
       w["mcpServers"]["fs"]["args"][:6] == ["-m", "legion_guard", "proxy", "--mode", "warn", "--"] and w["mcpServers"]["fs"]["args"][6:] ==
       ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"] and w["mcpServers"]["remote"] == cfg["mcpServers"]["remote"]
       and json.load(open(p)) == cfg, r.stdout[:300])
    json.dump(w, open(p, "w"))
    w2 = json.loads(subprocess.run([sys.executable, "-m", "legion_guard", "wrap-config", p], capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC)).stdout)
    ck("wrap-config : idempotent (pas de double enveloppe)", w2 == w)
    r = subprocess.run([sys.executable, "-m", "legion_guard", "check", "--help"], capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC))
    ck("CLI 0.2.x check inchangée", r.returncode == 0 and "approve" in r.stdout, r.stderr[-200:])

asyncio.run(main())
print("%d/%d" % (sum(R), len(R))); sys.exit(0 if all(R) else 1)
