#!/usr/bin/env python3
"""legion-lock — épingle les outils APPROUVÉS de serveurs MCP et détecte toute dérive, preuves signées à l'appui.

  legion_lock.py add SERVER_ID [--at-leaf N] [--at-head S]   épingle l'état observé (le plus récent, ou la feuille N),
                                               preuve contre la tête signée courante (ou celle de taille S)
  legion_lock.py check [--strict] [--json]     compare au journal public ; code 1 si dérive, avec le diff par outil
  legion_lock.py verify                        HORS LIGNE : revérifie les preuves stockées dans le lockfile
  legion_lock.py show                          affiche ce qui est épinglé

Source : journal de transparence LEGION (https://tlog.legion-api.com/tlog/v1). Ancre de confiance : empreinte de la clé
racine, épinglée ci-dessous (à recouper hors bande). Python 3.8+, bibliothèque standard ; `cryptography` utilisé s'il est
présent, sinon Ed25519 en Python pur (vendor/legion_verify_mirror.py, vecteurs RFC 8032 testés au chargement).
Codes de sortie : 0 = conforme ; 1 = dérive ; 2 = preuve invalide, réseau ou usage.
Ce que ça prouve : ce que LEGION a observé et signé pour ce serveur (l'observation d'UN observateur), et que l'historique
n'a pas été réécrit depuis votre épinglage. Ce que ça ne prouve pas : ce que le serveur montre à d'autres clients."""
import argparse, base64, datetime, difflib, hashlib, json, os, sys, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "vendor"))
import legion_tlog_verify as T  # noqa: E402  (vérifieur public, 369/369 vecteurs officiels)

try:
    import cryptography  # noqa: F401
except ImportError:                                   # pas de dépendance obligatoire : Ed25519 pur Python
    import legion_verify_mirror as _V                 # noqa: E402
    assert _V.ed_selftest() is not False
    T.ed25519_ok = lambda pub, sig, msg: _V.ed_verify_pure(pub, sig, msg)

FORMAT = "mcp-tools-lock/0.1"
DEFAULT_LOCK = ".mcp-tools.lock.json"
BASE = os.environ.get("LEGION_LOCK_BASE", "https://tlog.legion-api.com/tlog/v1").rstrip("/")
ROOT_PIN = "a7c6a35b1c2c81d589a30c2ad628679bdea9da4139d49aa3c42cdde6e1c65036"
FIELDS = ("name", "description", "inputSchema")


class Fail(Exception):
    pass


def get(path, raw=False):
    url = BASE + path
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "legion-lock/0.1"}), timeout=30) as r:
                b = r.read(8 << 20)
            return b.decode("utf-8") if raw else json.loads(b)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                import time; time.sleep(min(int(e.headers.get("Retry-After") or 5), 30)); continue
            raise Fail("journal : HTTP %d sur %s" % (e.code, path))
        except (urllib.error.URLError, OSError) as e:
            if attempt < 2:
                import time; time.sleep(3); continue
            raise Fail("journal injoignable (%s)" % type(e).__name__)


def keys_from(keyring_text):
    first = json.loads(next(l for l in keyring_text.splitlines() if l.strip()))
    if T.key_pin(first.get("public_key_b64", "")) != ROOT_PIN:
        raise Fail("trousseau : la 1re entrée n'a pas l'empreinte racine épinglée %s…" % ROOT_PIN[:16])
    return T.load_keyring(keyring_text, first["public_key_b64"])


def check_evidence(ev, keys, server_id):
    """Preuve = enregistrement signé + inclusion RFC 9162 + tête signée, clés issues de la racine épinglée."""
    res = T.verify_bundle_offline({"record": ev["record"], "inclusion": ev["inclusion"], "sth": ev["sth"]}, keys)
    if not res["ok"]:
        bad = [k for k in ("record_integrity", "record_signature", "head_signature", "inclusion") if not res.get(k)]
        raise Fail("%s : preuve REJETÉE (%s)" % (server_id, ", ".join(bad)))
    if ev["record"].get("server_id") != server_id:
        raise Fail("%s : la preuve concerne un autre serveur (%s)" % (server_id, ev["record"].get("server_id")))
    return res


def canon_for(algo):
    return T.canon_v1 if algo.endswith("/v1") else T.canon


def tools_from_archive(fp):
    """Définitions archivées, ACCEPTÉES seulement si elles redonnent l'empreinte signée."""
    try:
        tools = get("/tools/" + fp["sha256"])["tools"]
    except Fail:
        return None
    lst = sorted(({k: t[k] for k in FIELDS if k in t} for t in tools), key=lambda t: t["name"])
    if hashlib.sha256(canon_for(fp["algo"])(lst)).hexdigest() != fp["sha256"]:
        raise Fail("archive /tools/%s… : le contenu ne redonne pas l'empreinte signée" % fp["sha256"][:12])
    return {t["name"]: t for t in lst}


def approved_view(rec):
    fp = rec["tools_fingerprint"]
    return {"tools_sha256": fp["sha256"], "algo": fp["algo"], "tool_count": len(fp["per_tool_sha256"]),
            "tools": {n: h for n, h in fp["per_tool_sha256"]}}


def load_lock(p):
    if not os.path.exists(p):
        return {"format": FORMAT, "log": {"base": BASE, "origin": "tlog.legion-api.com/mcp/v0", "root_pin_sha256": ROOT_PIN},
                "keyring": None, "servers": {}}
    d = json.load(open(p, encoding="utf-8"))
    if d.get("format") != FORMAT:
        raise Fail("%s : format inconnu %r" % (p, d.get("format")))
    if d["log"]["root_pin_sha256"] != ROOT_PIN:
        raise Fail("%s : empreinte racine différente de celle de cet outil" % p)
    return d


def save_lock(p, d):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1, ensure_ascii=False, sort_keys=True); f.write("\n")
    os.replace(tmp, p)


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- commandes
def cmd_add(a):
    lock = load_lock(a.lock)
    kr = get("/keyring", raw=True); keys = keys_from(kr)
    sid = a.server_id
    if a.at_leaf is None and a.at_head is None:
        b = get("/servers/%s/latest" % urllib.parse.quote(sid, safe=""))
        ev = {"record": b["record"], "inclusion": b["inclusion"], "sth": b["sth"]}
    else:
        if a.at_leaf is None:
            rec = get("/servers/%s/latest" % urllib.parse.quote(sid, safe=""))["record"]
        else:
            rec = get("/records/%d" % a.at_leaf); rec = rec.get("record", rec)
        h = get("/head/%d" % a.at_head) if a.at_head is not None else get("/head"); sth = h.get("sth", h)
        n = sth["tree_head"]["tree_size"]
        ev = {"record": rec, "inclusion": get("/proof/inclusion?leaf_index=%d&tree_size=%d" % (rec["leaf_index"], n)), "sth": sth}
    check_evidence(ev, keys, sid)
    ap = approved_view(ev["record"])
    lock["keyring"] = kr
    lock["servers"][sid] = {"approved": ap, "evidence": ev, "pinned_at": now(),
                            "pinned_from": {"leaf_index": ev["record"]["leaf_index"], "observed_at": ev["record"]["observed_at"],
                                            "tree_size": ev["sth"]["tree_head"]["tree_size"]}}
    save_lock(a.lock, lock)
    print("ÉPINGLÉ %s : %d outils, empreinte %s… (feuille %d, observée %s), preuve vérifiée contre la racine %s…"
          % (sid, ap["tool_count"], ap["tools_sha256"][:16], ev["record"]["leaf_index"], ev["record"]["observed_at"], ROOT_PIN[:16]))
    return 0


def schema_paths(a, b, path=""):
    """Chemins JSON qui diffèrent entre deux schémas (ajout, retrait, valeur)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            p = "%s.%s" % (path, k) if path else k
            if k not in a: out.append("+ " + p)
            elif k not in b: out.append("- " + p)
            else: out += schema_paths(a[k], b[k], p)
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [x for i, (u, v) in enumerate(zip(a, b)) for x in schema_paths(u, v, "%s[%d]" % (path, i))]
    return [] if a == b else ["~ " + (path or "(racine)")]


def describe_drift(ap, rec):
    cur = approved_view(rec)
    old_t, new_t = ap["tools"], cur["tools"]
    added = sorted(set(new_t) - set(old_t)); removed = sorted(set(old_t) - set(new_t))
    modified = sorted(n for n in set(old_t) & set(new_t) if old_t[n] != new_t[n])
    lines, real_mod = [], []
    olda = newa = None
    if modified or ap["algo"] != cur["algo"]:
        olda = tools_from_archive({"sha256": ap["tools_sha256"], "algo": ap["algo"]})
        newa = tools_from_archive({"sha256": cur["tools_sha256"], "algo": cur["algo"]})
    for n in added:
        d = (newa or {}).get(n, {}).get("description", "")
        lines.append("outil %s : AJOUTÉ%s" % (n, (" — « %s »" % d[:120]) if d else ""))
    for n in removed:
        lines.append("outil %s : RETIRÉ" % n)
    for n in modified:
        if olda is None or newa is None:
            lines.append("outil %s : définition changée (archive indisponible : champ non déterminé)" % n); real_mod.append(n); continue
        x, y = olda[n], newa[n]
        if x == y:                                     # même contenu, empreinte recalculée autrement (changement d'algo)
            lines.append("outil %s : contenu IDENTIQUE (empreinte différente seulement par l'algorithme %s -> %s)" % (n, ap["algo"][-3:], cur["algo"][-3:]))
            continue
        real_mod.append(n)
        if x.get("description") != y.get("description"):
            lines.append("outil %s : description changée" % n)
            for l in difflib.unified_diff((x.get("description") or "").split(". "), (y.get("description") or "").split(". "), "approuvée", "actuelle", n=0, lineterm=""):
                if not l.startswith(("---", "+++", "@@")):
                    lines.append("    " + l[:160])
        if x.get("inputSchema") != y.get("inputSchema"):
            ps = schema_paths(x.get("inputSchema"), y.get("inputSchema"))
            lines.append("outil %s : inputSchema changé (%d chemin(s)) : %s" % (n, len(ps), ", ".join(ps[:8]) + (" …" if len(ps) > 8 else "")))
    return {"added": added, "removed": removed, "modified": real_mod, "lines": lines,
            "approved_sha256": ap["tools_sha256"], "current_sha256": cur["tools_sha256"]}


def cmd_check(a):
    lock = load_lock(a.lock)
    if not lock["servers"]:
        raise Fail("%s : aucun serveur épinglé (legion_lock.py add SERVER_ID)" % a.lock)
    keys = keys_from(get("/keyring", raw=True))
    report, drift, warn = [], 0, 0
    for sid, ent in sorted(lock["servers"].items()):
        check_evidence(ent["evidence"], keys, sid)                      # l'épinglage lui-même reste prouvé
        b = get("/servers/%s/latest" % urllib.parse.quote(sid, safe=""))
        cur = {"record": b["record"], "inclusion": b["inclusion"], "sth": b["sth"]}
        check_evidence(cur, keys, sid)
        m, n = ent["evidence"]["sth"]["tree_head"]["tree_size"], cur["sth"]["tree_head"]["tree_size"]
        rm, rn = ent["evidence"]["sth"]["tree_head"]["root_sha256"], cur["sth"]["tree_head"]["root_sha256"]
        if m < n:
            pr = get("/proof/consistency?old_size=%d&new_size=%d" % (m, n))["proof"]
            if not T._verify_consistency(m, n, bytes.fromhex(rm), bytes.fromhex(rn), [bytes.fromhex(h) for h in pr]):
                raise Fail("%s : HISTORIQUE RÉÉCRIT — la tête %d n'étend pas la tête %d de votre épinglage" % (sid, n, m))
        elif m == n and rm != rn:
            raise Fail("%s : FOURCHE — deux racines signées pour la taille %d" % (sid, m))
        elif m > n:
            raise Fail("%s : RETOUR EN ARRIÈRE — le journal sert la taille %d < %d déjà vue" % (sid, n, m))
        ent_r = {"server_id": sid, "pinned_leaf": ent["pinned_from"]["leaf_index"], "current_leaf": cur["record"]["leaf_index"],
                 "observed_at": cur["record"]["observed_at"], "head": n, "append_only_since_pin": True}
        if cur["record"]["tools_fingerprint"]["sha256"] == ent["approved"]["tools_sha256"]:
            ent_r["status"] = "CONFORME"
        else:
            d = describe_drift(ent["approved"], cur["record"])
            if d["added"] or d["removed"] or d["modified"]:
                ent_r.update(status="DÉRIVE", drift=d); drift += 1
            else:
                ent_r.update(status="CONFORME", note="empreinte recalculée autrement, contenu identique", drift=d)
        if b.get("newer_uncovered_records"):
            ent_r["warning"] = "%d observation(s) plus récente(s) pas encore dans une tête signée" % b["newer_uncovered_records"]; warn += 1
        report.append(ent_r)
    if a.json:
        print(json.dumps({"ok": drift == 0 and not (a.strict and warn), "servers": report}, indent=1, ensure_ascii=False))
    else:
        for r in report:
            print("%-9s %s  (épinglé feuille %d ; actuel feuille %d, observé %s ; tête signée %d, append-only vérifié)"
                  % (r["status"], r["server_id"], r["pinned_leaf"], r["current_leaf"], r["observed_at"], r["head"]))
            for l in (r.get("drift") or {}).get("lines", []):
                print("   " + l)
            if r.get("warning"):
                print("   attention : " + r["warning"])
        print("RÉSULTAT : %s" % ("DÉRIVE sur %d serveur(s)" % drift if drift else "aucune dérive"))
    return 1 if drift or (a.strict and warn) else 0


def cmd_verify(a):
    lock = load_lock(a.lock)
    keys = keys_from(lock["keyring"] or "")
    for sid, ent in sorted(lock["servers"].items()):
        res = check_evidence(ent["evidence"], keys, sid)
        if approved_view(ent["evidence"]["record"]) != ent["approved"]:
            raise Fail("%s : l'état « approuvé » du lockfile ne correspond pas à l'enregistrement signé" % sid)
        print("OK %s : feuille %d incluse dans la tête signée %d ; %d outils, empreinte %s… (hors ligne)"
              % (sid, res["leaf_index"], res["tree_size"], ent["approved"]["tool_count"], ent["approved"]["tools_sha256"][:16]))
    print("RÉSULTAT : %d épinglage(s) prouvé(s) hors ligne contre la racine %s…" % (len(lock["servers"]), ROOT_PIN[:16]))
    return 0


def cmd_show(a):
    lock = load_lock(a.lock)
    for sid, ent in sorted(lock["servers"].items()):
        print("%s : %d outils, %s…, feuille %d, épinglé %s" % (sid, ent["approved"]["tool_count"], ent["approved"]["tools_sha256"][:16],
                                                           ent["pinned_from"]["leaf_index"], ent["pinned_at"]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="legion-lock", description=__doc__.split("\n")[0])
    ap.add_argument("--lock", default=DEFAULT_LOCK)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("add"); s.add_argument("server_id"); s.add_argument("--at-leaf", type=int); s.add_argument("--at-head", type=int, help="prouver contre la tête signée de cette taille")
    s = sub.add_parser("check"); s.add_argument("--strict", action="store_true"); s.add_argument("--json", action="store_true")
    sub.add_parser("verify"); sub.add_parser("show")
    a = ap.parse_args(argv)
    try:
        return {"add": cmd_add, "check": cmd_check, "verify": cmd_verify, "show": cmd_show}[a.cmd](a)
    except Fail as e:
        print("ÉCHEC : %s" % e, file=sys.stderr); return 2
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
        print("ÉCHEC : donnée invalide (%s: %s)" % (type(e).__name__, e), file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
