"""
Règles de détection du WAF.

Chaque règle est un dictionnaire :
  - id       : identifiant unique
  - category : catégorie d'attaque (sqli, xss, path_traversal, cmd_injection, scanner)
  - name     : libellé lisible
  - severity : poids de la règle (contribue au score de la requête)
  - targets  : parties de la requête à inspecter
               (url, query, body, cookies, user_agent)
  - pattern  : expression régulière (insensible à la casse)

Le moteur additionne la severity de toutes les règles déclenchées.
Si le score >= seuil et que le mode est "block", la requête est bloquée.
"""

import re

# Catégories exposées au dashboard (ordre = ordre d'affichage)
CATEGORIES = {
    "sqli": "Injection SQL",
    "xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Traversée de répertoire",
    "cmd_injection": "Injection de commande",
    "scanner": "Scanner / Outil offensif",
}

RAW_RULES = [
    # ---------------------------------------------------------------- SQLi
    {
        "id": "SQLI-001",
        "category": "sqli",
        "name": "Contournement d'authentification (OR 1=1)",
        "severity": 5,
        "targets": ["query", "body"],
        "pattern": r"(?:'|\"|\s)\s*or\s+['\"]?\s*\d+\s*['\"]?\s*=\s*['\"]?\s*\d+",
    },
    {
        "id": "SQLI-002",
        "category": "sqli",
        "name": "UNION SELECT",
        "severity": 5,
        "targets": ["query", "body"],
        "pattern": r"union\s+(?:all\s+)?select",
    },
    {
        "id": "SQLI-003",
        "category": "sqli",
        "name": "Fonctions temporelles (SLEEP/BENCHMARK)",
        "severity": 4,
        "targets": ["query", "body"],
        "pattern": r"(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
    },
    {
        "id": "SQLI-004",
        "category": "sqli",
        "name": "Accès au schéma d'information",
        "severity": 4,
        "targets": ["query", "body"],
        "pattern": r"information_schema|sysobjects|pg_catalog",
    },
    {
        "id": "SQLI-005",
        "category": "sqli",
        "name": "Commentaire SQL en fin d'injection",
        "severity": 2,
        "targets": ["query", "body"],
        "pattern": r"(?:--\s|#|/\*).*(?:select|union|or|and)",
    },
    # ----------------------------------------------------------------- XSS
    {
        "id": "XSS-001",
        "category": "xss",
        "name": "Balise <script>",
        "severity": 5,
        "targets": ["query", "body", "url"],
        "pattern": r"<\s*script[^>]*>",
    },
    {
        "id": "XSS-002",
        "category": "xss",
        "name": "Gestionnaire d'événement JS (onerror/onload...)",
        "severity": 4,
        "targets": ["query", "body", "url"],
        "pattern": r"on(?:error|load|mouseover|focus|click)\s*=",
    },
    {
        "id": "XSS-003",
        "category": "xss",
        "name": "Pseudo-protocole javascript:",
        "severity": 4,
        "targets": ["query", "body", "url"],
        "pattern": r"javascript\s*:",
    },
    {
        "id": "XSS-004",
        "category": "xss",
        "name": "Injection via balise image/svg",
        "severity": 3,
        "targets": ["query", "body", "url"],
        "pattern": r"<\s*(?:img|svg|iframe|body)[^>]*(?:src|onerror|onload)",
    },
    # -------------------------------------------------------- Path traversal
    {
        "id": "PATH-001",
        "category": "path_traversal",
        "name": "Séquence ../ (remontée d'arborescence)",
        "severity": 4,
        "targets": ["query", "body", "url"],
        "pattern": r"(?:\.\./|\.\.\\){1,}",
    },
    {
        "id": "PATH-002",
        "category": "path_traversal",
        "name": "Cible de fichier système sensible",
        "severity": 5,
        "targets": ["query", "body", "url"],
        "pattern": r"etc/passwd|etc/shadow|/proc/self|win\.ini|boot\.ini",
    },
    {
        "id": "PATH-003",
        "category": "path_traversal",
        "name": "Encodage d'échappement (%2e%2e)",
        "severity": 3,
        "targets": ["query", "body", "url"],
        "pattern": r"%2e%2e|%252e|\.\.%2f",
    },
    # ------------------------------------------------------- Command injection
    {
        "id": "CMD-001",
        "category": "cmd_injection",
        "name": "Chaînage de commande shell (; | &&)",
        "severity": 5,
        "targets": ["query", "body"],
        "pattern": r"(?:;|\||&&|\|\|)\s*(?:cat|ls|id|whoami|uname|ping|curl|wget|nc|bash|sh|python)\b",
    },
    {
        "id": "CMD-002",
        "category": "cmd_injection",
        "name": "Substitution de commande $(...) ou backticks",
        "severity": 4,
        "targets": ["query", "body"],
        "pattern": r"\$\([^)]*\)|`[^`]*`",
    },
    {
        "id": "CMD-003",
        "category": "cmd_injection",
        "name": "Lecture de fichier sensible via commande",
        "severity": 4,
        "targets": ["query", "body"],
        "pattern": r"(?:cat|less|more|head|tail)\s+/(?:etc|var|root)",
    },
    # ------------------------------------------------------------- Scanners
    {
        "id": "SCAN-001",
        "category": "scanner",
        "name": "User-Agent d'outil offensif connu",
        "severity": 5,
        "targets": ["user_agent"],
        "pattern": r"sqlmap|nikto|nmap|acunetix|dirbuster|gobuster|masscan|wpscan|hydra|nuclei|zaproxy",
    },
]


def compile_rules():
    """Compile les patterns une seule fois au démarrage."""
    compiled = []
    for r in RAW_RULES:
        compiled.append({**r, "regex": re.compile(r["pattern"], re.IGNORECASE)})
    return compiled


COMPILED_RULES = compile_rules()
