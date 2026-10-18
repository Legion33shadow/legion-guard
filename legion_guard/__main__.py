"""CLI : python3 -m legion_guard check|approve URL SERVER_ID [--lock FICHIER] [--mode warn|block] [--no-legion]
check   : se connecte (initialize + tools/list, aucun tools/call), affiche le rapport ; code 0 conforme, 1 écart, 2 erreur
approve : écrit l'approbation de la liste reçue maintenant dans le lockfile (après revue humaine)"""
import argparse, asyncio, json, sys
import legion_guard as G


async def _tools(url):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    async with streamable_http_client(url) as (r, w, *_):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return (await s.list_tools()).tools


def main(argv=None):
    ap = argparse.ArgumentParser(prog="legion_guard")
    ap.add_argument("cmd", choices=["check", "approve"]); ap.add_argument("url"); ap.add_argument("server_id")
    ap.add_argument("--lock", default=G.L.DEFAULT_LOCK); ap.add_argument("--no-legion", action="store_true")
    a = ap.parse_args(argv)
    try:
        tools = asyncio.run(_tools(a.url))
    except Exception as e:
        print(json.dumps({"ok": None, "error": "connexion MCP impossible : %s" % type(e).__name__})); return 2
    if a.cmd == "approve":
        fp = G.approve(a.server_id, tools, a.lock); print("approuvé : %s (%d outils, %s…) -> %s" % (a.server_id, len(fp["per_tool"]), fp["sha256"][:16], a.lock)); return 0
    rep = G.evaluate(a.server_id, tools, a.lock, not a.no_legion)
    print(json.dumps(rep, indent=1, ensure_ascii=False))
    bad = rep["approval"] == "DIFFERS_FROM_APPROVED" or (rep.get("legion") or {}).get("state") == "DIFFERS_FROM_SIGNED"
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
