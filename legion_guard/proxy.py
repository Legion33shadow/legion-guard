"""Proxy stdio : legion-guard pour N'IMPORTE QUEL client MCP (Claude Code, Cursor, Codex CLI, Gemini CLI, …), sans code.

Dans la config MCP du client, on remplace la commande du serveur par :
    python3 -m legion_guard proxy [--server-id ID] [--mode warn|block] -- <commande du serveur> [args…]
ou, pour un serveur distant (streamable HTTP), le client voit un serveur stdio et le proxy parle HTTP au serveur :
    python3 -m legion_guard proxy --url https://… [--server-id ID] [--mode warn|block]
Le proxy lance le serveur (ou s'y connecte), relaie le JSON-RPC ligne à ligne dans les deux sens, et inspecte chaque réponse à tools/list :
  1. empreinte des outils (name, description, inputSchema ; même règle que le journal LEGION) comparée aux sources
     (premier usage local ; journal LEGION signé si --server-id) et à la liste vue en début de session ;
  2. annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) comparées à la première vue de ce serveur :
     l'empreinte ne les couvre pas, or un client peut s'y fier pour décider ce qu'il exécute sans demander.
     « relâchée » = vers moins de prudence (readOnly faux→vrai, destructive vrai→faux, openWorld vrai→faux).
warn (défaut) : rapport sur stderr + journal JSONL, rien n'est modifié. block (opt-in) : les outils modifiés, nouveaux ou à
annotation relâchée sont retirés de tools/list et leurs tools/call reçoivent une erreur JSON-RPC sans atteindre le serveur.
Fail-open : toute erreur interne du garde est journalisée, le trafic passe tel quel. Le proxy ne fait aucun tools/call.
Limites : côté client, stdio seulement ; côté serveur, stdio ou streamable HTTP sans en-têtes d'authentification ; un changement n'est pas une attaque ; rien ici ne certifie qu'un serveur est sûr."""
import hashlib, json, os, subprocess, sys, threading, time
import legion_guard as G

HINTS = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}   # défauts de la spec MCP
RELAXED = {"readOnlyHint": (False, True), "destructiveHint": (True, False), "openWorldHint": (True, False)}
ERR_BLOCKED = -32001


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def hints_of(tool):
    a = tool.get("annotations") or {}
    return {k: bool(a[k]) if isinstance(a.get(k), bool) else d for k, d in HINTS.items()}


def hint_changes(before, after):
    """before/after : {outil: {hint: bool}} -> liste des changements d'annotations des outils présents des deux côtés."""
    out = []
    for name in sorted(set(before) & set(after)):
        for h in HINTS:
            a, b = before[name].get(h, HINTS[h]), after[name].get(h, HINTS[h])
            if a != b:
                out.append({"tool": name, "hint": h, "before": a, "after": b, "relaxed": RELAXED.get(h) == (a, b)})
    return out


class HintPins:
    """Annotations de la première liste vue par serveur (fichier local, aucun réseau)."""

    def __init__(self, path):
        self.path, self._lock = path, threading.Lock()

    def check(self, sid, hints):
        with self._lock:
            pins = json.load(open(self.path)) if os.path.exists(self.path) else {}
            ref = pins.get(sid)
            if ref is None:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                pins[sid] = {"tools": hints, "first_seen": _now()}
                tmp = self.path + ".tmp"; json.dump(pins, open(tmp, "w"), indent=1, sort_keys=True); os.replace(tmp, self.path)
                return {"state": "PINNED_NOW", "changes": []}
            ch = hint_changes(ref["tools"], hints)
            # un outil apparu depuis l'épinglage est épinglé à sa première vue (les nouveaux outils sont déjà signalés par l'empreinte)
            new = {n: h for n, h in hints.items() if n not in ref["tools"]}
            if new:
                ref["tools"].update(new)
                tmp = self.path + ".tmp"; json.dump(pins, open(tmp, "w"), indent=1, sort_keys=True); os.replace(tmp, self.path)
            return {"state": "DIFFERS" if ch else "MATCHES", "changes": ch, "since": ref.get("first_seen")}


class Proxy:
    def __init__(self, cmd, server_id=None, mode="warn", cache=None, use_legion=True, audit=None, out=None, inp=None, url=None):
        if mode not in ("warn", "block"):
            raise ValueError("mode : warn | block")
        cache = cache or os.path.join(os.path.expanduser("~"), ".cache", "legion-guard")
        self.cmd, self.mode, self.url = cmd, mode, url
        # sans identifiant de registre, la référence locale est indexée par l'URL ou par la commande exacte du serveur
        self.sid = server_id or ("url:" + url if url else
                                 "cmd:" + hashlib.sha256(json.dumps(cmd).encode()).hexdigest()[:16] + ":" + os.path.basename(cmd[0]))
        sources = [G.FirstUseSource(os.path.join(cache, "pins.json"))] + ([G.LegionSource()] if server_id and use_legion else [])
        self.guard = G.GuardedSession(None, self.sid, sources, mode)
        self.hints = HintPins(os.path.join(cache, "hints.json"))
        self.audit = audit or os.path.join(cache, "proxy-audit.jsonl")
        self.out, self.inp = out or sys.stdout.buffer, inp or sys.stdin.buffer
        self._wlock, self._pending, self._pages, self._hint_blocked = threading.Lock(), {}, [], set()
        self.reports = []

    # ---------- sorties ----------
    def _to_client(self, obj_or_bytes):
        b = obj_or_bytes if isinstance(obj_or_bytes, bytes) else (json.dumps(obj_or_bytes, separators=(",", ":")) + "\n").encode()
        with self._wlock:
            self.out.write(b); self.out.flush()

    def _log(self, ev):
        ev = dict(ev, at=_now(), server_id=self.sid, mode=self.mode)
        try:
            os.makedirs(os.path.dirname(self.audit), exist_ok=True)
            with open(self.audit, "a") as f:
                f.write(json.dumps(ev, sort_keys=True) + "\n")
        except OSError:
            pass
        if ev.get("verdict") == "CHANGE_DETECTED" or ev.get("hint_changes"):
            sys.stderr.write("legion-guard: %s: %s changed=%s hints=%s (mode=%s)\n" % (
                self.sid, ev.get("verdict"), ev.get("changed_tools"),
                ["%s.%s %s->%s" % (c["tool"], c["hint"], c["before"], c["after"]) for c in ev.get("hint_changes", [])], self.mode))

    @property
    def blocked(self):
        return set(self.guard._blocked) | self._hint_blocked

    # ---------- inspection ----------
    def _on_full_list(self, tools):
        first = self.guard.report is None
        if first:
            self.guard._evaluate(tools)
            self.guard._session_fp = self.guard._fp_or_none(tools)
        else:
            self.guard._check_session_change(tools)
        rep = dict(self.guard.report or {})
        h = self.hints.check(self.sid, {t["name"]: hints_of(t) for t in tools if isinstance(t, dict) and "name" in t})
        rep["hints"] = {"state": h["state"], "since": h.get("since")}
        rep["hint_changes"] = h["changes"]
        if any(c["relaxed"] for c in h["changes"]):
            rep["verdict"] = "CHANGE_DETECTED"
        if self.mode == "block":
            self._hint_blocked |= {c["tool"] for c in h["changes"] if c["relaxed"]}
            rep["hidden_tools"] = sorted(self.blocked)
        rep["event"] = "tools/list" if first else "tools/list (same session)"
        self.reports.append(rep)
        self._log({k: v for k, v in rep.items() if k != "claim_boundary"})

    def _inspect_response(self, msg):
        """Réponse serveur -> éventuellement modifiée (block). Ne lève jamais."""
        try:
            if msg.get("id") not in self._pending or not isinstance(msg.get("result"), dict):
                self._pending.pop(msg.get("id"), None)
                return msg
            cursor = self._pending.pop(msg["id"])
            tools = msg["result"].get("tools")
            if not isinstance(tools, list):
                return msg
            if cursor is None:
                self._pages = []
            self._pages.extend(tools)
            if not msg["result"].get("nextCursor"):
                self._on_full_list(list(self._pages))
            b = self.blocked
            if b:
                msg["result"]["tools"] = [t for t in tools if not (isinstance(t, dict) and t.get("name") in b)]
            return msg
        except Exception as e:
            sys.stderr.write("legion-guard: internal error %s; not blocking\n" % type(e).__name__)
            return msg

    def _inspect_request(self, msg):
        """Requête client -> (à transmettre ?, réponse directe éventuelle)."""
        try:
            m = msg.get("method")
            if m == "tools/list" and "id" in msg:
                self._pending[msg["id"]] = (msg.get("params") or {}).get("cursor")
            elif m == "tools/call" and "id" in msg:
                name = (msg.get("params") or {}).get("name")
                if name in self.blocked:
                    self._log({"event": "tools/call refused", "tool": name})
                    return False, {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": ERR_BLOCKED,
                                   "message": "legion-guard: tool %r changed since it was first seen (mode=block); see %s" % (name, self.audit)}}
        except Exception as e:
            sys.stderr.write("legion-guard: internal error %s; not blocking\n" % type(e).__name__)
        return True, None

    # ---------- boucle ----------
    def _pump_server(self, proc):
        for line in iter(proc.stdout.readline, b""):
            try:
                msg = json.loads(line)
            except ValueError:
                self._to_client(line); continue
            if isinstance(msg, dict) and "id" in msg and "method" not in msg:
                self._to_client(self._inspect_response(msg))
            elif isinstance(msg, list):
                self._to_client([self._inspect_response(x) if isinstance(x, dict) and "method" not in x else x for x in msg])
            else:
                self._to_client(line)

    async def _run_http(self):
        """Client stdio <-> serveur streamable HTTP (transport du SDK MCP), mêmes inspections qu'en stdio."""
        import anyio
        from pydantic import TypeAdapter
        from mcp.client.streamable_http import streamable_http_client
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage
        ta = TypeAdapter(JSONRPCMessage)

        def as_dict(m):
            return m.model_dump(by_alias=True, mode="json", exclude_unset=True)

        async with streamable_http_client(self.url) as (read, write, *_):
            async def down():
                async for item in read:
                    if isinstance(item, Exception):
                        sys.stderr.write("legion-guard: transport error %s\n" % type(item).__name__); continue
                    d = as_dict(item.message)
                    self._to_client(self._inspect_response(d) if "id" in d and "method" not in d else d)

            async with anyio.create_task_group() as tg:
                tg.start_soon(down)
                while True:
                    line = await anyio.to_thread.run_sync(self.inp.readline)
                    if not line:
                        break
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        continue
                    for x in msg if isinstance(msg, list) else [msg]:
                        if not isinstance(x, dict):
                            continue
                        fwd, direct = self._inspect_request(x)
                        if direct is not None:
                            self._to_client(direct)
                        if fwd:
                            await write.send(SessionMessage(ta.validate_python(x)))
                tg.cancel_scope.cancel()
        return 0

    def run(self):
        if self.url:
            import anyio
            try:
                return anyio.run(self._run_http)
            except Exception as e:
                sys.stderr.write("legion-guard: cannot reach %s (%s)\n" % (self.url, type(e).__name__)); return 1
        proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        t = threading.Thread(target=self._pump_server, args=(proc,), daemon=True); t.start()
        try:
            for line in iter(self.inp.readline, b""):
                try:
                    msg = json.loads(line)
                except ValueError:
                    proc.stdin.write(line); proc.stdin.flush(); continue
                fwd, direct = True, None
                if isinstance(msg, dict):
                    fwd, direct = self._inspect_request(msg)
                elif isinstance(msg, list):
                    keep = []
                    for x in msg:
                        f, d = self._inspect_request(x) if isinstance(x, dict) else (True, None)
                        keep.append(x) if f else self._to_client(d)
                    line = (json.dumps(keep, separators=(",", ":")) + "\n").encode() if keep else b""
                    fwd = bool(keep)
                if direct is not None:
                    self._to_client(direct)
                if fwd:
                    proc.stdin.write(line); proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                rc = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate(); rc = proc.wait()
            t.join(timeout=2)
        return rc


def wrap_config(cfg, mode="warn", python=None, http=False):
    """Config MCP au format {"mcpServers": {...}} (Claude Code, Cursor, Claude Desktop…) -> même config, chaque serveur stdio
    passant par le proxy ; avec http=True, aussi chaque serveur streamable HTTP sans en-têtes (un en-tête d'authentification
    ne passe pas par la ligne de commande). Ne touche pas aux serveurs SSE ni aux serveurs déjà enveloppés. Renvoie (config, enveloppés)."""
    cfg = json.loads(json.dumps(cfg))
    done = []
    for name, s in (cfg.get("mcpServers") or {}).items():
        if (http and isinstance(s, dict) and s.get("type") in ("http", "streamable-http") and s.get("url")
                and not s.get("headers") and "command" not in s):
            cfg["mcpServers"][name] = {"command": python or sys.executable,
                                       "args": ["-m", "legion_guard", "proxy", "--mode", mode, "--url", s["url"]]}
            done.append(name)
            continue
        if not isinstance(s, dict) or "command" not in s or s.get("type") in ("http", "sse", "streamable-http"):
            continue
        args = s.get("args") or []
        if "legion_guard" in args[:2]:
            continue
        s["args"] = ["-m", "legion_guard", "proxy", "--mode", mode, "--", s["command"]] + list(args)
        s["command"] = python or sys.executable
        done.append(name)
    return cfg, done


def main(argv):
    import argparse
    if "--url" in argv and "--" not in argv:
        ap = argparse.ArgumentParser(prog="legion_guard proxy")
        ap.add_argument("--url", required=True); ap.add_argument("--server-id"); ap.add_argument("--mode", default="warn", choices=["warn", "block"])
        ap.add_argument("--no-legion", action="store_true"); ap.add_argument("--cache")
        a = ap.parse_args(argv)
        return Proxy(None, a.server_id, a.mode, a.cache, not a.no_legion, url=a.url).run()
    if "--" not in argv:
        sys.stderr.write("usage: python3 -m legion_guard proxy [--server-id ID] [--mode warn|block] [--no-legion] -- CMD [ARGS…]\n"
                         "       python3 -m legion_guard proxy --url URL [--server-id ID] [--mode warn|block] [--no-legion]\n"
                         "       python3 -m legion_guard wrap-config CONFIG.json [--mode warn|block]   (affiche, n'écrit rien)\n")
        return 2
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="legion_guard proxy")
    ap.add_argument("--server-id"); ap.add_argument("--mode", default="warn", choices=["warn", "block"])
    ap.add_argument("--no-legion", action="store_true"); ap.add_argument("--cache")
    a = ap.parse_args(argv[:i])
    if not argv[i + 1:]:
        sys.stderr.write("legion_guard proxy: commande du serveur manquante après --\n"); return 2
    return Proxy(argv[i + 1:], a.server_id, a.mode, a.cache, not a.no_legion).run()


def main_wrap_config(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="legion_guard wrap-config")
    ap.add_argument("config"); ap.add_argument("--mode", default="warn", choices=["warn", "block"])
    ap.add_argument("--http", action="store_true", help="also wrap streamable HTTP servers without headers")
    a = ap.parse_args(argv)
    cfg, done = wrap_config(json.load(open(a.config)), a.mode, http=a.http)
    sys.stderr.write("legion-guard: %d serveur(s) stdio enveloppé(s) : %s ; rien n'est écrit, redirigez la sortie après relecture\n" % (len(done), done))
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
    return 0
