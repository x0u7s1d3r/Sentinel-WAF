# Sentinel WAF

WAF applicatif open source, moderne et simple à déployer, pensé pour les PME.
Détection par **analyse sémantique** (et non par simple regex), faibles faux
positifs, architecture extensible par moteurs.

> État : **v0.1** — la passerelle (reverse proxy Go) est opérationnelle et
> protège un backend via le moteur sémantique d'injection SQL. Voir la
> [feuille de route](#feuille-de-route).

## Pourquoi Sentinel

- **Sémantique, pas regex.** Le moteur tokenise les entrées et raisonne sur
  leur structure : il voit à travers l'obfuscation (`UN/**/ION`, casse, espaces)
  et ne se déclenche pas sur une phrase anodine contenant « select » ou « or ».
- **Simple.** Une commande pour démarrer, configuration minimale.
- **Extensible.** Chaque protection est un moteur enfichable derrière une
  interface unique.

## Démarrage rapide

### Sans Docker (développement)

```bash
# 1. la passerelle
go build -o gateway ./cmd/gateway
./gateway -config configs/config.json      # écoute sur :8080

# 2. pointer "upstream" (configs/config.json) vers l'appli à protéger
```

### Avec Docker

```bash
docker compose up -d --build
# passerelle : http://localhost:8080  (protège le service demo-target)
```

## Vérifier que ça marche

```bash
# supervision
curl http://localhost:8080/_sentinel/health
curl http://localhost:8080/_sentinel/stats

# requête légitime -> transmise
curl "http://localhost:8080/?q=hello"

# injection SQL obfusquée -> bloquée (403)
curl "http://localhost:8080/?id=1%20UNION/**/SELECT%20a,b%20FROM%20users"

# contournement d'authentification -> bloqué (403)
curl "http://localhost:8080/login?user=admin%27--"

# phrase anodine contenant des mots SQL -> passe (pas de faux positif)
curl "http://localhost:8080/?q=please%20select%20a%20red%20or%20blue%20shirt"
```

## Configuration (`configs/config.json`)

```json
{
  "listen": ":8080",
  "upstream": "http://127.0.0.1:8000",
  "mode": "block",
  "threshold": 4
}
```

- `mode` : `block` (bloque) ou `detect` (journalise seulement).
- `threshold` : score cumulé à partir duquel une requête est bloquée.

## Structure du dépôt

```
sentinel-waf/
├── cmd/gateway/        binaire de la passerelle
├── internal/
│   ├── proxy/          reverse proxy + pipeline WAF
│   ├── parser/         normalisation HTTP
│   ├── detector/       moteurs de détection (sémantique SQL, chaîne)
│   └── config/         configuration
├── configs/            fichiers de configuration
├── docker/             Dockerfile
├── docs/               ARCHITECTURE.md
├── web/                dashboard (à venir)
└── docker-compose.yml
```

## Tests

```bash
go test ./...        # inclut la batterie du moteur sémantique SQL
```

## Feuille de route

| Version | Contenu | État |
|---------|---------|------|
| v0.1 | Passerelle Go, moteur sémantique SQL, supervision | ✅ |
| v0.2 | XSS sémantique + heuristiques (traversée, cmd, SSRF, NoSQL, scanner), PostgreSQL, Redis | 🔜 |
| v0.3 | Dashboard React (accueil PME + onglet technique) | 🔜 |
| v0.4 | Mode apprentissage (réduction des faux positifs) | 🔜 |
| v0.5 | Intégration SOAR (Shuffle / TheHive / Elastic) | 🔜 |

Voir [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) pour le détail.

## Licence

À définir (MIT recommandée pour un projet open source destiné aux PME).
