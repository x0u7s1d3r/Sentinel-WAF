# WAF Intelligent — Démo temps réel

Pare-feu applicatif web (WAF) en reverse proxy, avec console de supervision
temps réel et lanceur d'attaques intégré. Conçu pour une démonstration en
journée porte ouverte : on lance une attaque d'un clic, on voit le WAF la
bloquer en direct.

## Architecture

```
   Console d'attaque / navigateur
              │
              ▼
   ┌──────────────────────┐        ┌────────────────────────┐
   │   WAF  (port 8080)   │  ────▶ │  Backend cible (8000)  │
   │  reverse proxy       │ requêtes│  application vulnérable │
   │  + moteur détection  │ propres │  (vulns SIMULÉES)      │
   │  + journal SQLite    │        └────────────────────────┘
   └──────────┬───────────┘
              │ API de contrôle /_waf
              ▼
   ┌──────────────────────┐
   │ Dashboard (5173)     │  React — supervision + lanceur
   └──────────────────────┘
```

- **`waf/`** — le pare-feu. Reverse proxy FastAPI : chaque requête est inspectée
  par le moteur de détection (`detection.py` + `rules.py`), journalisée
  (`database.py`), puis bloquée ou transmise au backend.
- **`backend/`** — l'application cible protégée. Elle **simule** des
  vulnérabilités (voir note ci-dessous).
- **`dashboard/`** — la console React : stats, flux d'événements live, lanceur
  d'attaques un-clic, gestion des règles et de la blocklist.

## Prérequis

- Python 3.10+
- Node.js 18+ (pour le dashboard)

## Lancement rapide

```bash
chmod +x run.sh
./run.sh
```

Puis ouvrir **http://127.0.0.1:5173**.

### Lancement manuel (3 terminaux)

```bash
# Terminal 1 — backend cible
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd backend && uvicorn vulnerable_app:app --port 8000

# Terminal 2 — WAF
source .venv/bin/activate
cd waf && uvicorn main:app --port 8080

# Terminal 3 — dashboard
cd dashboard && npm install && npm run dev
```

## Déroulé de démonstration suggéré (JPO)

1. **Poser le décor.** Montrer le dashboard vide, mode **Blocage** actif.
2. **Requête légitime** (bouton « Requête légitime ») → passe en vert
   (`AUTORISÉE`). « Le trafic normal n'est pas gêné. »
3. **Lancer une SQLi** (« Contournement de login ») → `BLOQUÉE` en rouge,
   les règles déclenchées s'affichent (SQLI-001…). Le flux à droite réagit
   en temps réel.
4. **Enchaîner** XSS, traversée de répertoire, injection de commande, scan
   sqlmap — chaque catégorie a son bouton.
5. **Le moment clé.** Basculer en mode **Détection**, relancer la même SQLi :
   cette fois elle *passe* et le panneau montre **le backend qui fuit la table
   des mots de passe**. → « Sans blocage, voilà ce qui arrive. » Revenir en
   Blocage : de nouveau bloquée.
6. **Pour le jury technique.** Ouvrir un terminal et attaquer le proxy
   directement, ça marche aussi :
   ```bash
   curl "http://127.0.0.1:8080/search?q=<script>alert(1)</script>"
   curl -A "sqlmap/1.7" "http://127.0.0.1:8080/products?id=1"
   ```
   Montrer les règles (`rules.py`), le scoring, le seuil ajustable, la
   désactivation d'une catégorie en direct.

## Note d'honnêteté (à assumer devant le jury)

Le **moteur de détection est réel** : ce sont de vraies expressions régulières
appliquées à de vrais payloads, avec un système de score et de seuil.

En revanche, l'application cible **simule** l'exploitation : elle n'exécute
aucune commande système et ne lit aucun fichier réel. Quand une charge passe
(WAF désactivé), le backend renvoie une réponse *pré-écrite* imitant une fuite
(faux `/etc/passwd`, fausse table SQL). C'est le choix responsable pour une
démo publique : rien d'exploitable ne tourne, mais le contraste
« bloqué / non bloqué » reste parlant.

## Personnalisation

- **Ajouter une règle** : éditer `waf/rules.py` (id, catégorie, sévérité,
  cibles, pattern regex). Rechargée au redémarrage du WAF.
- **Protéger une vraie appli** : changer `BACKEND_URL` dans `waf/main.py`.
- **Ajuster le seuil** de blocage : directement depuis le dashboard.

## Points d'API du WAF (pour référence)

| Méthode | Route                | Rôle                                  |
|---------|----------------------|---------------------------------------|
| GET     | `/_waf/stats`        | statistiques agrégées                 |
| GET     | `/_waf/events`       | flux d'événements                     |
| GET/POST| `/_waf/config`       | lire / modifier mode, seuil, règles   |
| GET     | `/_waf/attacks`      | catalogue d'attaques de démo          |
| POST    | `/_waf/simulate`     | rejouer une attaque                   |
| GET/POST| `/_waf/blocklist`    | gérer les IP bloquées                 |
| POST    | `/_waf/reset`        | vider le journal                      |
```
