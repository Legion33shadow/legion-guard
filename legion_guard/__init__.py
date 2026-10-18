"""legion-guard — verify-before-connect pour les clients MCP.

Avant qu'un agent utilise les outils d'un serveur MCP, le garde compare la liste d'outils RÉELLEMENT reçue par CE client :
  1. aux outils que vous avez approuvés (lockfile `.mcp-tools.lock.json`, format mcp-tools-lock/0.1, le même que legion-lock) ;
  2. à la dernière liste signée par le journal public LEGION (enregistrement + preuve d'inclusion RFC 9162 + tête signée,
     clés issues de la racine épinglée) — un écart signifie que ce client reçoit autre chose que ce que LEGION a observé
     (changement depuis la dernière sonde, ou contenu différent selon le client).
Mode "warn" : rapport seulement. Mode "block" : les outils non approuvés ou modifiés sont retirés de list_tools() et leur
appel est refusé (ToolNotApproved). Lecture seule vis-à-vis du serveur : aucun tools/call n'est fait par le garde.
Limites : LEGION n'observe qu'une partie des serveurs ; absence du journal n'est pas un verdict. Un changement n'est pas une
attaque. Rien ici ne certifie qu'un serveur est sûr."""
import hashlib, json, os, sys, urllib.parse
_H = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _H)
import _lock as L  # noqa: E402  (legion-lock : vérifieur, trousseau, lockfile)
T = L.T
__version__ = "0.2.3"
FIELDS = ("name", "description", "inputSchema")
ALGO = "sha256(JCS-RFC8785(sorted[{name,description,inputSchema}]))/v2"


class ToolNotApproved(Exception):
    pass


def _tool_dict(t):
    d = t if isinstance(t, dict) else t.model_dump(by_alias=True, exclude_none=True)
    return {k: d[k] for k in FIELDS if k in d and d[k] is not None}


def fingerprint(tools, algo=ALGO):
    """Empreinte d'une liste tools/list, même règle que le journal LEGION (par outil et liste complète)."""
    c = L.canon_for(algo)
    ts = sorted((_tool_dict(t) for t in tools), key=lambda t: t["name"])
    return {"sha256": hashlib.sha256(c(ts)).hexdigest(), "algo": algo,
            "per_tool": {t["name"]: hashlib.sha256(c(t)).hexdigest() for t in ts}}


def legion_signed(server_id):
    """Dernier enregistrement signé par LEGION pour ce serveur, preuve vérifiée. None si absent du journal."""
    try:
        b = L.get("/servers/%s/latest" % urllib.parse.quote(server_id, safe=""))
    except L.Fail as e:
        if "HTTP 404" in str(e):
            return None
        raise
    keys = L.keys_from(L.get("/keyring", raw=True))
    L.check_evidence({"record": b["record"], "inclusion": b["inclusion"], "sth": b["sth"]}, keys, server_id)
    fp = b["record"]["tools_fingerprint"]
    return {"sha256": fp["sha256"], "algo": fp["algo"], "per_tool": dict(fp["per_tool_sha256"]),
            "observed_at": b["record"]["observed_at"], "leaf_index": b["record"]["leaf_index"],
            "tree_size": b["sth"]["tree_head"]["tree_size"]}


def evaluate(server_id, tools, lockfile=L.DEFAULT_LOCK, use_legion=True):
    live = fingerprint(tools)
    rep = {"server_id": server_id, "live_tools_sha256": live["sha256"], "tool_count": len(live["per_tool"]), "tools": {}}
    approved = None
    if lockfile and os.path.exists(lockfile):
        ap = (L.load_lock(lockfile).get("servers", {}).get(server_id) or {}).get("approved")
        if ap:
            approved = ap
            if ap.get("algo") and ap["algo"] != live["algo"]:
                live = fingerprint(tools, ap["algo"]); rep["live_tools_sha256"] = live["sha256"]
    for n, h in live["per_tool"].items():
        if approved is None:
            rep["tools"][n] = "NOT_APPROVED"
        elif n not in approved["tools"]:
            rep["tools"][n] = "NEW"
        else:
            rep["tools"][n] = "APPROVED" if approved["tools"][n] == h else "CHANGED"
    if approved is not None:
        rep["removed_since_approval"] = sorted(set(approved["tools"]) - set(live["per_tool"]))
    rep["approval"] = ("NO_APPROVAL" if approved is None else
                       "MATCHES_APPROVED" if approved["tools_sha256"] == live["sha256"] else "DIFFERS_FROM_APPROVED")
    if use_legion:
        try:
            s = legion_signed(server_id)
            if s is None:
                rep["legion"] = {"state": "UNKNOWN", "reason": "no signed record for this id; absence from the log is not a verdict"}
            else:
                lv = live if s["algo"] == live["algo"] else fingerprint(tools, s["algo"])
                diff = sorted(n for n in set(lv["per_tool"]) | set(s["per_tool"]) if lv["per_tool"].get(n) != s["per_tool"].get(n))
                rep["legion"] = {"state": "MATCHES_SIGNED" if lv["sha256"] == s["sha256"] else "DIFFERS_FROM_SIGNED",
                                 "signed_observed_at": s["observed_at"], "leaf_index": s["leaf_index"], "tree_size": s["tree_size"],
                                 "proof": "record signature + RFC 9162 inclusion + signed head, verified from the pinned root key",
                                 "differing_tools": diff}
                if diff:
                    rep["legion"]["meaning"] = ("this client receives a tool list that LEGION did not sign: either the server changed "
                                                "since LEGION's last probe, or it serves different tools to different clients")
        except L.Fail as e:
            rep["legion"] = {"state": "UNVERIFIED", "reason": str(e)}
    rep["claim_boundary"] = ("LEGION observes only part of the servers; absence from the log is not a verdict. "
                             "A change is not an attack. This does not certify that a server is secure.")
    return rep


def approve(server_id, tools, lockfile=L.DEFAULT_LOCK, note="approved from the live tools/list"):
    """Écrit (ou remplace) l'approbation de ce serveur avec la liste reçue maintenant — à faire après revue humaine."""
    live = fingerprint(tools)
    d = L.load_lock(lockfile)
    d.setdefault("servers", {})[server_id] = {"approved": {"tools_sha256": live["sha256"], "algo": live["algo"],
                                              "tool_count": len(live["per_tool"]), "tools": live["per_tool"]},
                                              "approved_at": L.now(), "source": note}
    L.save_lock(lockfile, d)
    return live


async def guard_session(session, server_id, lockfile=L.DEFAULT_LOCK, mode="warn", use_legion=True, on_report=None):
    """À appeler après session.initialize(). Évalue la liste réelle ; en mode "block", ne laisse passer que les outils
    APPROUVÉS (list_tools filtré, call_tool refusé sinon). Renvoie le rapport."""
    if mode not in ("warn", "block"):
        raise ValueError("mode : warn | block")
    res = await session.list_tools()
    rep = evaluate(server_id, res.tools, lockfile, use_legion)
    rep["mode"] = mode
    if on_report:
        on_report(rep)
    if mode == "block":
        allowed = {n for n, s in rep["tools"].items() if s == "APPROVED"}
        ap_hash = (L.load_lock(lockfile)["servers"].get(server_id) or {}).get("approved", {}).get("tools", {}) if lockfile and os.path.exists(lockfile) else {}
        rep["exposed_tools"] = sorted(allowed)
        orig_list, orig_call = session.list_tools, session.call_tool

        async def list_tools(*a, **k):
            r = await orig_list(*a, **k)
            r.tools = [t for t in r.tools if t.name in allowed and fingerprint([t])["per_tool"][t.name] == ap_hash.get(t.name)]
            return r

        async def call_tool(name, *a, **k):
            if name not in allowed:
                raise ToolNotApproved("%s : tool %r is %s (not approved in %s)" % (server_id, name, rep["tools"].get(name, "UNKNOWN"), lockfile))
            return await orig_call(name, *a, **k)
        session.list_tools, session.call_tool = list_tools, call_tool
    return rep


# ---------- 0.2 : une ligne, observe par défaut, ne casse jamais l'application, sources interchangeables ----------
import logging as _logging
log = _logging.getLogger("legion_guard")
from .sources import PinnedSource, FirstUseSource, LegionSource  # noqa: E402,F401


def default_sources(server_id=None):
    """Confiance au premier usage (local) + journal LEGION si l'identifiant de registre est connu. Remplaçable."""
    return [FirstUseSource()] + ([LegionSource()] if server_id else [])


class GuardedSession:
    """Enveloppe une mcp.ClientSession. Au premier list_tools(), compare la liste reçue à chaque source ; aux list_tools()
    suivants de la même session, compare aussi à la liste du début de session (un serveur peut la changer après quelques appels).
    mode="warn" (défaut) : journalise et rapporte, ne retire RIEN. mode="block" (opt-in) : retire de list_tools() et refuse
    dans call_tool() les outils pour lesquels une source a la PREUVE d'un changement (DIFFERS / nouvel outil) ; une source
    UNKNOWN ou UNAVAILABLE ne bloque jamais (fail-open). Toute exception interne du garde est avalée et journalisée."""

    def __init__(self, session, server_id=None, sources=None, mode="warn", on_report=None):
        if mode not in ("warn", "block"):
            raise ValueError("mode : warn | block")
        self._s, self.server_id, self.mode, self.on_report = session, server_id, mode, on_report
        self.sources = default_sources(server_id) if sources is None else list(sources)
        self.report, self._blocked = None, set()

    def __getattr__(self, k):
        return getattr(self._s, k)

    def _evaluate(self, tools):
        try:
            sid = self.server_id or ("server-info:%s" % getattr(getattr(self._s, "server_info", None) or object(), "name", "unknown"))
            fp = fingerprint(tools); fp["_recompute"] = lambda algo: fingerprint(tools, algo)
            rep = {"server_id": sid, "mode": self.mode, "live_tools_sha256": fp["sha256"], "tool_count": len(fp["per_tool"]), "sources": {}}
            for src in self.sources:
                try:
                    rep["sources"][getattr(src, "name", type(src).__name__)] = src.check(sid, fp)
                except Exception as e:  # une source cassée ne casse pas l'agent
                    rep["sources"][getattr(src, "name", type(src).__name__)] = {"state": "UNAVAILABLE", "reason": type(e).__name__}
            changed = set()
            for r in rep["sources"].values():
                if r.get("state") == "DIFFERS":
                    changed |= set(r.get("tools", [])) | set(r.get("new", []))
            rep["changed_tools"] = sorted(changed & set(fp["per_tool"]))
            rep["verdict"] = "CHANGE_DETECTED" if changed else ("UNVERIFIED" if all(r.get("state") in ("UNKNOWN", "UNAVAILABLE", "PINNED_NOW") for r in rep["sources"].values()) else "NO_CHANGE_DETECTED")
            rep["claim_boundary"] = ("LEGION observes only part of the servers; absence from the log is not a verdict. A change is not an attack. "
                                     "This does not certify that a server is secure.")
            self._blocked = set(rep["changed_tools"]) if self.mode == "block" else set()
            rep["hidden_tools"] = sorted(self._blocked)
            for name, r in rep["sources"].items():
                if r.get("state") == "UNAVAILABLE":
                    log.warning("legion-guard: source %s unavailable (%s); not blocking", name, r.get("reason"))
            if changed:
                log.warning("legion-guard: %s: tool change detected %s (mode=%s)", sid, rep["changed_tools"], self.mode)
            self.report = rep
            if self.on_report:
                self.on_report(rep)
        except Exception as e:   # fail-open : le garde ne fait jamais échouer l'application
            log.warning("legion-guard: internal error %s; not blocking", type(e).__name__)
            self.report, self._blocked = {"verdict": "GUARD_ERROR", "error": type(e).__name__}, set()

    async def list_tools(self, *a, **k):
        r = await self._s.list_tools(*a, **k)
        if self.report is None:
            self._evaluate(r.tools)
            self._session_fp = self._fp_or_none(r.tools)
        elif not (a or k.get("cursor") or getattr(k.get("params"), "cursor", None)):   # page 1 seulement : une page suivante n'est pas un changement
            self._check_session_change(r.tools)
        if self._blocked:
            r.tools = [t for t in r.tools if t.name not in self._blocked]
        return r

    @staticmethod
    def _fp_or_none(tools):
        try:
            return fingerprint(tools)
        except Exception:
            return None

    def _check_session_change(self, tools):
        """Même session, nouveau tools/list : comparaison à la liste vue au début de la session. warn : rapport seulement ;
        block : retire et refuse les outils modifiés ou nouveaux. Fail-open, comme _evaluate."""
        try:
            fp, ref = fingerprint(tools), getattr(self, "_session_fp", None)
            if ref is None or fp["sha256"] == ref["sha256"]:
                return
            ch = sorted(n for n, h in fp["per_tool"].items() if ref["per_tool"].get(n) != h)
            new = sorted(set(ch) - set(self.report.get("mid_session_changed_tools", [])))
            if not new:
                return
            self.report["verdict"] = "CHANGE_DETECTED"
            self.report["mid_session_changed_tools"] = sorted(set(self.report.get("mid_session_changed_tools", [])) | set(ch))
            self.report["changed_tools"] = sorted(set(self.report.get("changed_tools", [])) | set(ch))
            log.warning("legion-guard: %s: tool list changed during the session %s (mode=%s)", self.report.get("server_id"), new, self.mode)
            if self.mode == "block":
                self._blocked |= set(ch)
                self.report["hidden_tools"] = sorted(self._blocked)
            if self.on_report:
                self.on_report(self.report)
        except Exception as e:
            log.warning("legion-guard: internal error %s; not blocking", type(e).__name__)

    async def call_tool(self, name, *a, **k):
        if self.report is None:
            await self.list_tools()
        if name in self._blocked:
            raise ToolNotApproved("%s: tool %r changed according to %s (mode=block)" % (self.server_id, name,
                                  [n for n, r in self.report["sources"].items() if r.get("state") == "DIFFERS"]))
        return await self._s.call_tool(name, *a, **k)


def wrap(session, server_id=None, sources=None, mode="warn", on_report=None):
    """Une ligne : session = legion_guard.wrap(session, "io.example/server"). Observe par défaut ; block = opt-in."""
    return GuardedSession(session, server_id, sources, mode, on_report)
