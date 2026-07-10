# Sentinel WAF

**Pare-feu applicatif web (WAF) open source, moderne et simple à déployer, pensé pour les PME.**

Sentinel se place devant vos applications web comme un reverse-proxy et inspecte
chaque requête en temps réel. Il détecte et bloque les attaques (injections,
XSS, traversées de répertoire, scanners…), vous alerte, et enrichit chaque
incident d'une **analyse en langage naturel** produite par une IA.

Le tout se pilote depuis une **console web** : aucune ligne de commande n'est
nécessaire pour l'exploitation quotidienne.

---

## Fonctionnalités

- **9 familles de détection** : injection SQL, XSS, traversée de répertoire,
  injection de commande, SSRF, injection NoSQL, scanners offensifs, accès aux
  chemins sensibles, force brute — par **analyse sémantique** (pas de simple
  regex), pour peu de faux positifs.
- **Multi-applications** : protégez plusieurs sites, chacun avec son domaine,
  son mode (blocage ou surveillance) et son seuil.
- **Console d'administration** : supervision temps réel, graphes, score de
  menace, gestion des applications et de toute la configuration.
- **Alertes Slack & Discord** : notifications enrichies (gravité, application
  visée, analyse IA, mesures immédiates), configurables depuis la console.
- **Enrichissement IA** : analyse des attaques via une API compatible OpenAI
  (Groq, RodiumAI, OpenAI, Ollama…).
- **Authentification** : accès à la console protégé par mot de passe.
- **Rétention automatique** des événements, **survie au redémarrage**,
  dégradation gracieuse (le WAF continue même si la base ou l'IA est indisponible).

---

## Démarrage rapide

**Prérequis :** [Docker](https://docs.docker.com/engine/install/) et Docker
Compose (inclus dans Docker Desktop, ou le paquet `docker-compose-plugin`).

```bash
git clone https://github.com/x0u7s1d3r/Sentinel-WAF.git
cd Sentinel-WAF
./start.sh
```

Le script vérifie les prérequis, crée le fichier de configuration, construit les
images et démarre l'ensemble. À la fin, il affiche les adresses d'accès :

- **Console d'administration** : <http://localhost:3000>
- **Passerelle WAF (proxy)** : <http://localhost:8000>

À la première visite de la console, **créez votre compte administrateur**, puis
ajoutez vos applications à protéger depuis l'onglet **Applications**.

> Sans Docker Compose v2 (`docker compose`), le script utilise automatiquement
> `docker-compose` (v1) s'il est présent.

---

## Configuration

Toute la configuration se fait de **deux façons**, au choix :

1. **Depuis la console web** (recommandé) — alertes, IA, applications, compte…
   tout est modifiable à chaud, sans redémarrage.
2. **Via le fichier `.env`** — pratique pour un déploiement automatisé. Copié
   depuis `.env.example` au premier lancement. Il contient des **secrets** et
   n'est jamais versionné (présent dans `.gitignore`).

Principales variables (toutes facultatives, valeurs par défaut sûres) :

| Variable | Rôle |
|---|---|
| `SENTINEL_ADMIN_PASSWORD` | Mot de passe de la console (sinon défini au 1er lancement) |
| `SENTINEL_HTTP_PORT` / `SENTINEL_DASHBOARD_PORT` | Ports d'accès (défaut 8000 / 3000) |
| `SENTINEL_SLACK_WEBHOOK` / `SENTINEL_DISCORD_WEBHOOK` | Alertes (aussi configurables via la console) |
| `LLM_ENABLED` / `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` | Enrichissement IA |
| `SENTINEL_RETENTION_DAYS` / `SENTINEL_RETENTION_MAX` | Rétention des événements |
| `POSTGRES_PASSWORD` | Mot de passe de la base (interne) |

---

## Ajouter une application à protéger

1. Déployez votre application (ou pointez vers une application existante).
2. Dans la console → **Applications** → **Ajouter** :
   - **Nom** : un libellé lisible.
   - **Domaine** : l'en-tête `Host` du trafic à router (ex. `boutique.exemple.tg`).
   - **Backend** : l'URL interne de votre application (ex. `http://mon-app:80`).
   - **Mode** : *Blocage* (arrête les attaques) ou *Surveillance* (détecte sans bloquer).
3. Faites pointer ce domaine vers la passerelle Sentinel (DNS, ou `/etc/hosts`
   en test). Le trafic est désormais inspecté.

---

## Architecture

- **Passerelle** (Go) : reverse-proxy inspectant le trafic. Compilée, concurrente,
  latence de l'ordre de la microseconde.
- **Console** (React) : plan de contrôle, séparé du plan de données.
- **PostgreSQL** : persistance des événements et de la configuration.

Le trafic Internet traverse la passerelle (qui l'inspecte via ses moteurs de
détection) avant d'atteindre vos applications. Les événements et la configuration
sont stockés dans PostgreSQL, et la console web lit/écrit cette configuration.

---

## Dépannage

**La console ne se met pas à jour après une modification.**
Videz le cache du navigateur (Ctrl+Maj+R) ou utilisez une fenêtre de navigation
privée.

**Sur une machine virtuelle : « cannot stop container: permission denied ».**
Certaines VM avec Docker installé via *snap* subissent un blocage AppArmor.
Correctif :

```bash
sudo systemctl edit docker
# Ajoutez ces deux lignes puis enregistrez :
#   [Service]
#   AppArmorProfile=
sudo systemctl restart docker
```

**Voir les journaux :**

```bash
docker compose logs -f gateway     # ou : docker-compose logs -f gateway
```

**Arrêter / redémarrer :**

```bash
docker compose down                # arrêter
./start.sh                         # redémarrer
```

---

## Développement

Environnement de test avec application volontairement vulnérable (dossier
`attack-lab/`) pour éprouver la détection.

Compilation manuelle de la passerelle (sans Docker) :

```bash
go build -o gateway ./cmd/gateway
./gateway -config configs/config.json
```

---

## Licence

MIT — voir [LICENSE](LICENSE).
