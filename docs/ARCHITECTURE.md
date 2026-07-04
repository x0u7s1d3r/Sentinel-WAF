# Sentinel WAF — Architecture

WAF applicatif open source pensé pour les PME : installation simple,
faibles faux positifs, extensible. Ce document décrit l'architecture cible
et l'état d'avancement réel.

## Principe directeur

Un WAF moderne ne repose plus sur des regex statiques. Sentinel combine
**analyse sémantique** (tokenisation et raisonnement sur la structure des
entrées) et **règles heuristiques**, dans un pipeline à score. La décision
de blocage dépend d'un score cumulé et d'un seuil, pas d'un match unique.

## Vue d'ensemble

```
        Internet
           │
   ┌───────▼────────┐
   │   Gateway      │  reverse proxy (Go, stdlib net/http)
   │  (cmd/gateway) │
   └───────┬────────┘
           │  parse → normalise
   ┌───────▼────────┐
   │    Parser      │  extrait/décode les valeurs (query, corps, chemin)
   └───────┬────────┘
           │  Request normalisée
   ┌───────▼────────┐
   │ Detection Chain│  agrège les moteurs, calcule le score
   │  ├ semantic-sql│  ← implémenté (tokeniseur multi-contexte)
   │  ├ semantic-xss│  ← implémenté (analyse structurelle HTML/JS)
   │  └ heuristics  │  ← implémenté (traversée, cmd, SSRF, NoSQL, scanner)
   └───────┬────────┘
           │  Result {findings, categories, score}
   ┌───────▼────────┐
   │ Decision       │  score ≥ seuil ? mode block/detect
   └───────┬────────┘
     allow │ block
           ▼
     Backend protégé
```

## Composants

| Paquet | Rôle | État |
|--------|------|------|
| `cmd/gateway` | binaire de la passerelle, supervision `/_sentinel/*` | ✅ |
| `internal/proxy` | reverse proxy + pipeline WAF (point d'accroche des moteurs) | ✅ |
| `internal/parser` | normalisation HTTP → `Request` (décodage, extraction) | ✅ |
| `internal/detector` | `Detector`/`Chain` + moteurs : SQL & XSS sémantiques, heuristiques (traversée, cmd, SSRF, NoSQL, scanner) | ✅ |
| `internal/config` | configuration JSON (listen, upstream, mode, seuil) | ✅ |
| `internal/logger` | journalisation structurée (slog) | intégré |
| `internal/storage` | persistance PostgreSQL des événements (écriture asynchrone, dégradation gracieuse) | ✅ |
| Redis (rate limit/cache) | à venir | 🔜 |
| dashboard `web/` | accueil PME + onglet technique (React) | 🔜 |

## Contrat de détection

Tout moteur implémente une interface unique — c'est ce qui rend le système
extensible (approche « plugins ») :

```go
type Detector interface {
    Name() string
    Inspect(value string) []Finding
}
```

Ajouter une protection = ajouter un `Detector` à la `Chain` dans
`cmd/gateway/main.go`, sans toucher au proxy ni au parser.

## Le moteur sémantique SQL

Cœur de la valeur ajoutée. Au lieu de chercher `UNION SELECT`, il tokenise
l'entrée (mots-clés, chaînes, nombres, opérateurs, commentaires…) et applique
des signatures **structurelles** : UNION SELECT, requête empilée, tautologie
(`OR 1=1`), fonction temporelle (`SLEEP`), sortie de contexte chaîne,
contournement d'auth (`admin'--`), évasion par commentaire inline.

L'analyse est **multi-contexte** (comme libinjection) : l'entrée est
retokenisée comme si elle était déjà à l'intérieur d'une chaîne SQL, ce qui
permet de « voir » les charges du type `1' OR '1'='1`.

Résultat : détection robuste à l'obfuscation (`UN/**/ION`, casse, espaces)
**et** très peu de faux positifs (une phrase contenant « select » ou « or »
ne forme aucune structure d'injection). Voir les tests
`internal/detector/semantic_sql_test.go`.

## Modèle de données (cible, couche stockage)

```
events(id, ts, client_ip, method, path, verdict, score, categories, findings, latency_us)
applications(id, name, upstream_url, mode, threshold, created_at)
blocklist(ip, reason, created_at)
```

## Feuille de route

- **v0.1 (actuel)** : passerelle Go + moteur sémantique SQL + supervision.
- **v0.2** : moteur XSS sémantique + heuristiques (traversée, cmd, SSRF, NoSQL,
  scanner) ; persistance PostgreSQL ; rate limiting Redis.
- **v0.3** : dashboard React (accueil PME « État du site » + onglet technique).
- **v0.4** : mode apprentissage (profil de trafic, réduction des faux positifs).
- **v0.5** : intégration SOAR (Shuffle / TheHive / Elastic).
```
