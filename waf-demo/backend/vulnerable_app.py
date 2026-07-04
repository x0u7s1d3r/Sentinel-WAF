"""
Application cible de démonstration.

IMPORTANT — lire avant la JPO :
Cette appli SIMULE des vulnérabilités. Elle n'exécute AUCUNE commande système
réelle et ne lit AUCUN fichier réel. Quand une charge malveillante est détectée
dans l'entrée, l'appli renvoie une réponse *pré-écrite* qui imite le résultat
d'une exploitation (ex. un faux /etc/passwd, une fausse fuite de table SQL).

But : montrer honnêtement le contraste "WAF désactivé -> l'attaque aboutit"
vs "WAF activé -> bloquée", sans laisser tourner du code réellement exploitable.
La détection côté WAF, elle, est bien réelle (vraies regex sur de vrais payloads).

Démarrage :  uvicorn vulnerable_app:app --port 8000
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(title="App vulnérable — Démo (simulée)")

FAKE_USERS = [
    {"id": 1, "username": "admin", "password": "S3cr3t_Adm1n!"},
    {"id": 2, "username": "amiir", "password": "waf_master_2025"},
    {"id": 3, "username": "invite", "password": "guest123"},
]

FAKE_PRODUCTS = {
    "1": {"id": 1, "name": "Routeur FortiGate 60F", "prix": "780000 FCFA"},
    "2": {"id": 2, "name": "Switch Cisco Catalyst 2960", "prix": "420000 FCFA"},
    "3": {"id": 3, "name": "Serveur Dell PowerEdge R450", "prix": "2100000 FCFA"},
}

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "amiir:x:1000:1000:Amiir,,,:/home/amiir:/bin/bash\n"
)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h2>Application de démonstration</h2>
    <p>Cible protégée par le WAF. Points d'entrée : /login, /products, /search,
    /download, /ping.</p>
    """


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))

    # Vulnérabilité SIMULÉE : une charge de contournement "réussit"
    if "'" in username and ("or" in username.lower() and "=" in username):
        return {
            "status": "authentifié",
            "message": "Connexion réussie en tant qu'admin (contournement SQLi)",
            "note": "SIMULÉ — aucune vraie base n'a été interrogée",
        }

    for u in FAKE_USERS:
        if u["username"] == username and u["password"] == password:
            return {"status": "authentifié", "user": username}
    return {"status": "refusé", "message": "identifiants invalides"}


@app.get("/products")
def products(id: str = "1"):
    # Vulnérabilité SIMULÉE : une charge UNION "fuit" la table users
    if "union" in id.lower() and "select" in id.lower():
        return {
            "leak": "SIMULÉ — extraction de la table users",
            "rows": [
                {"username": u["username"], "password": u["password"]}
                for u in FAKE_USERS
            ],
        }
    return FAKE_PRODUCTS.get(id.strip(), {"error": "produit introuvable"})


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Vulnérabilité SIMULÉE : réflexion non échappée de q dans la page.
    # (rendu comme texte de page, pas d'exécution côté serveur)
    return f"""
    <h3>Résultats pour : {q}</h3>
    <p>Aucun résultat. (Le terme est réfléchi tel quel : XSS réfléchi simulé.)</p>
    """


@app.get("/download")
def download(file: str = ""):
    # Vulnérabilité SIMULÉE : une traversée "renvoie" un faux passwd
    if "../" in file or "etc/passwd" in file or "..\\" in file:
        return PlainTextResponse(FAKE_PASSWD)
    return {"file": file, "content": "(fichier de démo vide)"}


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    # Vulnérabilité SIMULÉE : un chaînage de commande "exécute" cat /etc/passwd
    if any(sep in host for sep in [";", "|", "&", "`", "$("]):
        return PlainTextResponse(
            f"PING {host.split(';')[0]} : 64 bytes, temps=0.04 ms\n"
            f"--- résultat de la commande injectée (SIMULÉ) ---\n{FAKE_PASSWD}"
        )
    return PlainTextResponse(
        f"PING {host} : 64 bytes, temps=0.04 ms\n1 paquets transmis, 0 perdu"
    )
