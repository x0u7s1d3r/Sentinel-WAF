"""
WAF — reverse proxy applicatif.

Rôle :
  - intercepte chaque requête entrante
  - l'inspecte avec le moteur de détection
  - selon le mode (block / detect), bloque ou laisse passer
  - journalise l'événement
  - forwarde les requêtes légitimes vers le backend protégé

Expose aussi une API de contrôle sous /_waf pour le dashboard :
réglages, statistiques, flux d'événements, blocklist, et un lanceur
d'attaques de démonstration (/_waf/simulate).

Démarrage :  uvicorn main:app --port 8080
"""

import time
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse

import database as db
from detection import inspect
from rules import CATEGORIES, RAW_RULES

# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #
BACKEND_URL = "http://127.0.0.1:8000"   # appli cible protégée
CONTROL_PREFIX = "/_waf"

app = FastAPI(title="WAF Intelligent — Démo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # démo locale : le dashboard tourne sur un autre port
    allow_methods=["*"],
    allow_headers=["*"],
)

# La base doit exister avant de relire les réglages persistants
db.init_db()

# État runtime, rechargé depuis la base au démarrage
CONFIG = {
    "mode": db.load_setting("mode", "block"),          # "block" | "detect"
    "threshold": db.load_setting("threshold", 4),      # score déclenchant l'action
    "enabled_categories": set(
        db.load_setting("enabled_categories", list(CATEGORIES.keys()))
    ),
    "blocklist": set(db.load_setting("blocklist", [])),
}


def persist_config():
    db.save_setting("mode", CONFIG["mode"])
    db.save_setting("threshold", CONFIG["threshold"])
    db.save_setting("enabled_categories", sorted(CONFIG["enabled_categories"]))
    db.save_setting("blocklist", sorted(CONFIG["blocklist"]))


@app.on_event("startup")
def _startup():
    db.init_db()


# --------------------------------------------------------------------------- #
#  Catalogue d'attaques de démonstration (lanceur "un clic")
# --------------------------------------------------------------------------- #
ATTACK_CATALOG = {
    "sqli_login": {
        "label": "Contournement de login (SQLi)",
        "category": "sqli",
        "method": "POST",
        "path": "/login",
        "body": "username=admin' OR '1'='1&password=x",
        "content_type": "application/x-www-form-urlencoded",
        "explain": "Injecte OR '1'='1 pour valider la condition et se connecter sans mot de passe.",
    },
    "sqli_union": {
        "label": "Vol de données (UNION SELECT)",
        "category": "sqli",
        "method": "GET",
        "path": "/products?id=1 UNION SELECT username,password FROM users",
        "explain": "Détourne la requête pour extraire la table des utilisateurs.",
    },
    "xss_reflected": {
        "label": "XSS réfléchi",
        "category": "xss",
        "method": "GET",
        "path": "/search?q=<script>alert('XSS')</script>",
        "explain": "Injecte un script exécuté dans le navigateur de la victime.",
    },
    "path_traversal": {
        "label": "Traversée de répertoire",
        "category": "path_traversal",
        "method": "GET",
        "path": "/download?file=../../../../etc/passwd",
        "explain": "Remonte l'arborescence pour lire un fichier système sensible.",
    },
    "cmd_injection": {
        "label": "Injection de commande",
        "category": "cmd_injection",
        "method": "GET",
        "path": "/ping?host=127.0.0.1;cat /etc/passwd",
        "explain": "Chaîne une commande shell après le ping légitime.",
    },
    "scanner": {
        "label": "Scan automatisé (sqlmap)",
        "category": "scanner",
        "method": "GET",
        "path": "/products?id=1",
        "user_agent": "sqlmap/1.7.2#stable",
        "explain": "Détecté par la signature User-Agent de l'outil offensif.",
    },
    "legit": {
        "label": "Requête légitime (témoin)",
        "category": None,
        "method": "GET",
        "path": "/products?id=2",
        "explain": "Trafic normal : doit passer sans alerte.",
    },
}


# --------------------------------------------------------------------------- #
#  Cœur de l'inspection
# --------------------------------------------------------------------------- #
def evaluate(method, path, query, body, user_agent, cookies, client_ip):
    """
    Inspecte la requête et renvoie (verdict, résultat_détection).
    verdict ∈ {allowed, detected, blocked}
    """
    if client_ip in CONFIG["blocklist"]:
        result = {"matches": [], "categories": ["blocklist"], "score": 99}
        return "blocked", result

    result = inspect(
        {
            "url": path,
            "query": query,
            "body": body,
            "user_agent": user_agent,
            "cookies": cookies,
        },
        CONFIG["enabled_categories"],
    )

    triggered = result["score"] >= CONFIG["threshold"]
    if not triggered:
        verdict = "allowed"
    elif CONFIG["mode"] == "block":
        verdict = "blocked"
    else:  # mode détection : on signale mais on laisse passer
        verdict = "detected"

    return verdict, result


def record(client_ip, method, path, verdict, result, snippet):
    event_id = db.log_event(
        client_ip,
        method,
        path,
        verdict,
        result["score"],
        result["categories"],
        result["matches"],
        snippet[:300],
    )
    return event_id


BLOCK_PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Requête bloquée</title>
<style>
 body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
 .card{{max-width:520px;padding:2.5rem;border:1px solid #f8514933;border-radius:14px;
        background:#161b22;text-align:center}}
 h1{{color:#f85149;margin:.2rem 0 1rem;font-size:1.6rem}}
 code{{background:#0d1117;padding:.15rem .4rem;border-radius:5px;color:#ffa657}}
 .tag{{display:inline-block;background:#f8514922;color:#f85149;padding:.2rem .6rem;
       border-radius:20px;font-size:.8rem;margin:.2rem}}
</style></head>
<body><div class="card">
 <h1>&#9940; Requête bloquée par le WAF</h1>
 <p>La requête a été identifiée comme malveillante et n'a pas atteint l'application.</p>
 <p>Catégories : {cats}</p>
 <p>Score de menace : <code>{score}</code></p>
 <p style="opacity:.6;font-size:.85rem;margin-top:1.5rem">Identifiant incident : #{eid}</p>
</div></body></html>"""


# --------------------------------------------------------------------------- #
#  API de contrôle (dashboard)  —  déclarée AVANT le catch-all proxy
# --------------------------------------------------------------------------- #
@app.get(CONTROL_PREFIX + "/config")
def get_config():
    return {
        "mode": CONFIG["mode"],
        "threshold": CONFIG["threshold"],
        "enabled_categories": sorted(CONFIG["enabled_categories"]),
        "all_categories": CATEGORIES,
        "blocklist": sorted(CONFIG["blocklist"]),
        "backend_url": BACKEND_URL,
    }


@app.post(CONTROL_PREFIX + "/config")
async def set_config(request: Request):
    data = await request.json()
    if "mode" in data and data["mode"] in ("block", "detect"):
        CONFIG["mode"] = data["mode"]
    if "threshold" in data:
        try:
            CONFIG["threshold"] = max(1, int(data["threshold"]))
        except (TypeError, ValueError):
            pass
    if "enabled_categories" in data and isinstance(data["enabled_categories"], list):
        CONFIG["enabled_categories"] = {
            c for c in data["enabled_categories"] if c in CATEGORIES
        }
    persist_config()
    return get_config()


@app.get(CONTROL_PREFIX + "/rules")
def list_rules():
    return {
        "categories": CATEGORIES,
        "rules": [
            {k: v for k, v in r.items() if k != "pattern"} | {"pattern": r["pattern"]}
            for r in RAW_RULES
        ],
    }


@app.get(CONTROL_PREFIX + "/stats")
def stats():
    s = db.get_stats()
    s["config"] = {
        "mode": CONFIG["mode"],
        "threshold": CONFIG["threshold"],
        "active_rules": sum(
            1 for r in RAW_RULES if r["category"] in CONFIG["enabled_categories"]
        ),
        "total_rules": len(RAW_RULES),
    }
    return s


@app.get(CONTROL_PREFIX + "/events")
def events(limit: int = 100, since_id: int = 0):
    return {"events": db.get_events(limit=limit, since_id=since_id)}


@app.post(CONTROL_PREFIX + "/reset")
def reset():
    db.clear_events()
    return {"ok": True}


@app.get(CONTROL_PREFIX + "/blocklist")
def get_blocklist():
    return {"blocklist": sorted(CONFIG["blocklist"])}


@app.post(CONTROL_PREFIX + "/blocklist")
async def update_blocklist(request: Request):
    data = await request.json()
    ip = (data.get("ip") or "").strip()
    action = data.get("action", "add")
    if ip:
        if action == "add":
            CONFIG["blocklist"].add(ip)
        elif action == "remove":
            CONFIG["blocklist"].discard(ip)
        persist_config()
    return {"blocklist": sorted(CONFIG["blocklist"])}


@app.get(CONTROL_PREFIX + "/attacks")
def list_attacks():
    """Catalogue exposé au dashboard pour le lanceur un-clic."""
    return {
        "attacks": [
            {"id": k, **{kk: vv for kk, vv in v.items() if kk != "body"}}
            for k, v in ATTACK_CATALOG.items()
        ]
    }


@app.post(CONTROL_PREFIX + "/simulate")
async def simulate(request: Request):
    """
    Rejoue une attaque du catalogue à travers le pipeline de détection réel,
    puis (si non bloquée) la transmet au backend. Renvoie le résultat complet
    pour affichage immédiat dans le dashboard.
    """
    data = await request.json()
    attack_id = data.get("attack")
    attack = ATTACK_CATALOG.get(attack_id)
    if not attack:
        return JSONResponse({"error": "attaque inconnue"}, status_code=400)

    method = attack["method"]
    full_path = attack["path"]
    path, _, query = full_path.partition("?")
    body = attack.get("body", "")
    user_agent = attack.get("user_agent", "Mozilla/5.0 (Demo-WAF)")
    client_ip = "203.0.113.47"  # IP fictive "attaquant" pour la démo

    verdict, result = evaluate(
        method, path, query, body, user_agent, "", client_ip
    )
    snippet = full_path + ((" | " + body) if body else "")
    eid = record(client_ip, method, full_path, verdict, result, snippet)

    backend_response = None
    if verdict != "blocked":
        # On transmet réellement au backend pour montrer l'impact quand le WAF
        # laisse passer (mode détection ou catégorie désactivée).
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                headers = {"User-Agent": user_agent}
                if method == "POST":
                    headers["Content-Type"] = attack.get(
                        "content_type", "application/x-www-form-urlencoded"
                    )
                    r = await client.post(
                        BACKEND_URL + path, params=_parse_query(query),
                        content=body, headers=headers,
                    )
                else:
                    r = await client.get(
                        BACKEND_URL + path,
                        params=_parse_query(query),
                        headers=headers,
                    )
                backend_response = {
                    "status": r.status_code,
                    "snippet": r.text[:400],
                }
        except Exception as e:
            backend_response = {"status": 0, "snippet": f"backend injoignable: {e}"}

    return {
        "event_id": eid,
        "verdict": verdict,
        "score": result["score"],
        "categories": result["categories"],
        "matched": result["matches"],
        "attack": {"id": attack_id, "label": attack["label"], "explain": attack["explain"]},
        "backend_response": backend_response,
    }


def _parse_query(query: str) -> dict:
    out = {}
    for pair in query.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        out[k] = v
    return out


# --------------------------------------------------------------------------- #
#  Reverse proxy — catch-all (doit rester en DERNIER)
# --------------------------------------------------------------------------- #
@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy(full_path: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method
    path = "/" + full_path
    query = request.url.query
    raw_body = await request.body()
    body_text = raw_body.decode("utf-8", errors="ignore")
    user_agent = request.headers.get("user-agent", "")
    cookies = request.headers.get("cookie", "")

    verdict, result = evaluate(
        method, path, query, body_text, user_agent, cookies, client_ip
    )
    snippet = f"{path}?{query}" + ((" | " + body_text) if body_text else "")
    eid = record(client_ip, method, path, verdict, result, snippet)

    if verdict == "blocked":
        return HTMLResponse(
            BLOCK_PAGE.format(
                cats=", ".join(result["categories"]) or "règle générique",
                score=result["score"],
                eid=eid,
            ),
            status_code=403,
        )

    # Requête acceptée (ou détectée) : on transmet au backend protégé
    target = f"{BACKEND_URL}{path}"
    if query:
        target += f"?{query}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            proxied = await client.request(
                method,
                target,
                content=raw_body,
                headers={
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ("host", "content-length")
                },
            )
        return Response(
            content=proxied.content,
            status_code=proxied.status_code,
            headers={
                k: v for k, v in proxied.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
            },
        )
    except Exception as e:
        return JSONResponse(
            {"error": f"Backend injoignable ({e}). Lancez d'abord le backend de démo."},
            status_code=502,
        )
