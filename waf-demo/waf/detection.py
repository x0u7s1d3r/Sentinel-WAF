"""
Moteur de détection.

On lui passe une représentation normalisée de la requête HTTP, il renvoie
un verdict : liste des règles déclenchées, catégories touchées, score total.
La décision finale (bloquer ou laisser passer) est prise par main.py en
fonction du mode courant et du seuil.
"""

from urllib.parse import unquote_plus
from rules import COMPILED_RULES


def _decode(value: str) -> str:
    """
    Décode l'URL-encoding pour éviter les contournements triviaux
    (ex. %2e%2e au lieu de ..). On décode deux fois pour attraper
    le double-encodage courant.
    """
    if not value:
        return ""
    try:
        once = unquote_plus(value)
        twice = unquote_plus(once)
        # On garde les deux formes concaténées : une règle peut cibler
        # la forme encodée (PATH-003) comme la forme décodée.
        return f"{value} {once} {twice}"
    except Exception:
        return value


def inspect(request: dict, enabled_categories: set) -> dict:
    """
    request attend les clés :
      url          -> chemin brut
      query        -> chaîne de requête brute
      body         -> corps décodé (str)
      user_agent   -> valeur de l'en-tête User-Agent
      cookies      -> chaîne de cookies

    enabled_categories : ensemble des catégories actives (les autres sont ignorées)

    Retour :
      {
        "matches": [ {id, category, name, severity, target}, ... ],
        "categories": [...],
        "score": int
      }
    """
    fields = {
        "url": _decode(request.get("url", "")),
        "query": _decode(request.get("query", "")),
        "body": _decode(request.get("body", "")),
        "user_agent": request.get("user_agent", "") or "",
        "cookies": _decode(request.get("cookies", "")),
    }

    matches = []
    categories = set()
    score = 0

    for rule in COMPILED_RULES:
        if rule["category"] not in enabled_categories:
            continue
        for target in rule["targets"]:
            haystack = fields.get(target, "")
            if not haystack:
                continue
            if rule["regex"].search(haystack):
                matches.append(
                    {
                        "id": rule["id"],
                        "category": rule["category"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "target": target,
                    }
                )
                categories.add(rule["category"])
                score += rule["severity"]
                break  # une règle ne compte qu'une fois même si plusieurs champs matchent

    return {
        "matches": matches,
        "categories": sorted(categories),
        "score": score,
    }
