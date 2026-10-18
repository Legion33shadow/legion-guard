"""Sources de vérification interchangeables. Chaque source compare la liste d'outils reçue à SA référence et renvoie :
  MATCHES (même empreinte) | DIFFERS (+ outils concernés) | UNKNOWN (pas de référence pour ce serveur) | UNAVAILABLE (erreur réseau
  ou preuve illisible : jamais bloquant). LEGION est la source par défaut, pas une obligation : retirez-la, remplacez-la, ou
  ajoutez la vôtre (tout objet avec .name et .check(server_id, fp) -> dict)."""
import json, os, socket, threading, urllib.parse, urllib.request
from . import _lock as L
T = L.T
LEGION_V1 = "https://tlog.legion-api.com/tlog/v1"
LEGION_LOG_VKEY = "legion-mcp-tlog+cfc0988f+AfE4wYMFGnFlhk/ON4Qnf98XNiOTUJNJY3y08DAv9hxk"


def _per_tool_diff(a, b):
    return sorted(n for n in set(a) | set(b) if a.get(n) != b.get(n))


class PinnedSource:
    """Empreintes épinglées localement (aucun réseau). pins = dict {server_id: {"tools_sha256", "tools": {nom: sha}}} ou chemin
    d'un lockfile mcp-tools-lock/0.1 (legion-lock / legion_guard.approve)."""
    name = "pinned"

    def __init__(self, pins):
        self.pins = pins

    def _ref(self, sid):
        if isinstance(self.pins, dict):
            return self.pins.get(sid)
        if os.path.exists(self.pins):
            return ((L.load_lock(self.pins).get("servers") or {}).get(sid) or {}).get("approved")
        return None

    def check(self, sid, fp):
        ref = self._ref(sid)
        if not ref:
            return {"state": "UNKNOWN", "reason": "no pinned fingerprint for this server"}
        if ref.get("tools_sha256") == fp["sha256"]:
            return {"state": "MATCHES"}
        return {"state": "DIFFERS", "tools": _per_tool_diff(fp["per_tool"], ref.get("tools", {})),
                "new": sorted(set(fp["per_tool"]) - set(ref.get("tools", {}))), "removed": sorted(set(ref.get("tools", {})) - set(fp["per_tool"]))}


class FirstUseSource(PinnedSource):
    """Confiance au premier usage : la première liste vue pour un serveur est épinglée dans un fichier local (par défaut
    ~/.cache/legion-guard/pins.json) ; les connexions suivantes sont comparées à elle. Aucun réseau."""
    name = "first-use"

    def __init__(self, path=None):
        self.path = path or os.path.join(os.path.expanduser("~"), ".cache", "legion-guard", "pins.json")
        self._lock = threading.Lock()

    def check(self, sid, fp):
        with self._lock:
            pins = json.load(open(self.path)) if os.path.exists(self.path) else {}
            if sid not in pins:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                pins[sid] = {"tools_sha256": fp["sha256"], "tools": fp["per_tool"], "first_seen": L.now()}
                tmp = self.path + ".tmp"; json.dump(pins, open(tmp, "w"), indent=1, sort_keys=True); os.replace(tmp, self.path)
                return {"state": "PINNED_NOW", "reason": "first connection to this server: its tool list is now the local reference", "file": self.path}
        self.pins = pins
        r = PinnedSource.check(self, sid, fp)
        if r["state"] == "DIFFERS":
            r["since"] = pins[sid].get("first_seen")
        return r


class LegionSource:
    """Dernière liste signée par un journal au format LEGION tlog v1 (par défaut le journal public LEGION) : enregistrement +
    preuve d'inclusion RFC 9162 + tête signée, clés issues de la racine épinglée. Option C2SP : witnesses=[vkey, ...] et
    min_witnesses=N exigent que la tête soit celle d'un checkpoint (signed-note) signé par le journal et cosigné par N de VOS
    témoins. Délai court ; toute erreur -> UNAVAILABLE (jamais bloquant)."""
    name = "legion"

    def __init__(self, base=LEGION_V1, root_pin=L.ROOT_PIN, timeout=6, witnesses=None, min_witnesses=0, log_vkey=LEGION_LOG_VKEY):
        self.base, self.root_pin, self.timeout = base.rstrip("/"), root_pin, timeout
        self.witnesses, self.min_witnesses, self.log_vkey = list(witnesses or []), int(min_witnesses), log_vkey

    def _get(self, path, raw=False):
        req = urllib.request.Request(self.base + path, headers={"User-Agent": "legion-guard/0.2"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            b = r.read(8 << 20)
        return b.decode("utf-8") if raw else json.loads(b)

    def check(self, sid, fp):
        try:
            try:
                b = self._get("/servers/%s/latest" % urllib.parse.quote(sid, safe=""))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {"state": "UNKNOWN", "reason": "no signed record for this id; absence from the log is not a verdict"}
                raise
            kr = self._get("/keyring", raw=True)
            first = json.loads(next(l for l in kr.splitlines() if l.strip()))
            if T.key_pin(first.get("public_key_b64", "")) != self.root_pin:
                return {"state": "UNAVAILABLE", "reason": "keyring root does not match the pinned root key"}
            keys = T.load_keyring(kr, first["public_key_b64"])
            res = T.verify_bundle_offline({"record": b["record"], "inclusion": b["inclusion"], "sth": b["sth"]}, keys)
            if not res["ok"] or b["record"].get("server_id") != sid:
                return {"state": "UNAVAILABLE", "reason": "signed evidence did not verify"}
            out = {"signed_observed_at": b["record"]["observed_at"], "leaf_index": b["record"]["leaf_index"],
                   "tree_size": b["sth"]["tree_head"]["tree_size"], "proof": "record signature + RFC 9162 inclusion + signed head"}
            if self.min_witnesses > 0:
                note = self._get("/checkpoint", raw=True)
                w = T.verify_witnessed(note, self.log_vkey, self.witnesses, self.min_witnesses)
                if not w.get("ok"):
                    return dict(out, state="UNAVAILABLE", reason="checkpoint not cosigned by %d of your witnesses (%s)" % (self.min_witnesses, w.get("error") or w.get("witnesses_valid")))
                if (w["tree_size"], w["root_sha256"]) != (b["sth"]["tree_head"]["tree_size"], b["sth"]["tree_head"]["root_sha256"]):
                    return dict(out, state="UNAVAILABLE", reason="witnessed checkpoint and signed head differ in size or root (retry later)")
                out["witnessed_by"] = w["witnesses_valid"]
            fpl = b["record"]["tools_fingerprint"]
            if fpl["algo"] != fp["algo"]:
                fp = fp["_recompute"](fpl["algo"])
            if fpl["sha256"] == fp["sha256"]:
                return dict(out, state="MATCHES")
            return dict(out, state="DIFFERS", tools=_per_tool_diff(fp["per_tool"], dict(fpl["per_tool_sha256"])),
                        meaning="this client receives a tool list that the log did not sign: changed since the last probe, or served differently to different clients")
        except (urllib.error.URLError, OSError, socket.timeout, ValueError, KeyError, StopIteration) as e:
            return {"state": "UNAVAILABLE", "reason": "%s: %s" % (type(e).__name__, str(e)[:120])}
