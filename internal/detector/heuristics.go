package detector

import "regexp"

// Heuristics regroupe les détecteurs par règles (regex) pour les familles où
// la correspondance de motifs reste pertinente — y compris dans les WAF réels
// qui combinent sémantique et règles : traversée de répertoire, injection de
// commande, SSRF, injection NoSQL, détection de scanners.
type Heuristics struct {
	rules []heurRule
}

func (Heuristics) Name() string { return "heuristics" }

type heurRule struct {
	id, category, name, target string // target: "value" | "user_agent"
	severity                   int
	re                         *regexp.Regexp
}

// NewHeuristics compile l'ensemble des règles une fois.
func NewHeuristics() Heuristics {
	specs := []struct {
		id, category, name, target, pattern string
		severity                            int
	}{
		// -------- Traversée de répertoire --------
		{"PATH-001", "path_traversal", "Séquence ../ (remontée d'arborescence)", "value", `(?:\.\./|\.\.\\)+`, 4},
		{"PATH-002", "path_traversal", "Cible de fichier système sensible", "value", `etc/passwd|etc/shadow|/proc/self|win\.ini|boot\.ini`, 5},
		{"PATH-003", "path_traversal", "Encodage d'échappement (%2e%2e)", "value", `%2e%2e|%252e|\.\.%2f|%c0%ae`, 3},
		// -------- Injection de commande --------
		{"CMD-001", "cmd_injection", "Chaînage de commande shell (; | &&)", "value", `(?:;|\||&&|\|\|)\s*(?:cat|ls|id|whoami|uname|ping|curl|wget|nc|bash|sh|python|powershell)\b`, 5},
		{"CMD-002", "cmd_injection", "Substitution de commande $(...) ou backticks", "value", "\\$\\([^)]*\\)|`[^`]*`", 4},
		{"CMD-003", "cmd_injection", "Lecture de fichier sensible via commande", "value", `(?:cat|less|more|head|tail)\s+/(?:etc|var|root)`, 4},
		// -------- SSRF --------
		{"SSRF-001", "ssrf", "Accès aux métadonnées cloud (169.254.169.254)", "value", `169\.254\.169\.254|metadata\.google|/latest/meta-data`, 5},
		{"SSRF-002", "ssrf", "URL vers l'hôte local / le réseau interne", "value", `(?:https?|file|gopher|dict|ftp)://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|169\.254\.|10\.|192\.168\.)`, 4},
		{"SSRF-003", "ssrf", "Schéma d'URL dangereux (file:// gopher://)", "value", `(?:file|gopher|dict|ldap|jar)://`, 4},
		// -------- NoSQL --------
		{"NOSQL-001", "nosql", "Opérateur MongoDB ($ne, $gt, $where…)", "value", `\$(?:ne|gt|lt|gte|lte|regex|where|exists|in|nin|or|and)\b`, 5},
		{"NOSQL-002", "nosql", "Injection JavaScript NoSQL (';return / sleep)", "value", `';\s*return|sleep\(\d+\)|this\.\w+\s*==`, 4},
		// -------- Scanner --------
		{"SCAN-001", "scanner", "User-Agent d'outil offensif connu", "user_agent", `(?i)sqlmap|nikto|nmap|acunetix|dirbuster|gobuster|masscan|wpscan|hydra|nuclei|zaproxy|feroxbuster`, 5},
	}
	rules := make([]heurRule, 0, len(specs))
	for _, s := range specs {
		pat := s.pattern
		// insensible à la casse par défaut (sauf préfixe déjà présent)
		if len(pat) < 4 || pat[:4] != "(?i)" {
			pat = "(?i)" + pat
		}
		rules = append(rules, heurRule{
			id: s.id, category: s.category, name: s.name, target: s.target,
			severity: s.severity, re: regexp.MustCompile(pat),
		})
	}
	return Heuristics{rules: rules}
}

// Inspect applique les règles : celles ciblant "value" sur toutes les valeurs,
// celles ciblant "user_agent" sur l'en-tête User-Agent.
func (h Heuristics) Inspect(req Request) []Finding {
	var out []Finding
	for _, r := range h.rules {
		matched := false
		switch r.target {
		case "user_agent":
			matched = req.UserAgent != "" && r.re.MatchString(req.UserAgent)
		default: // "value"
			for _, v := range req.Values {
				if r.re.MatchString(v) {
					matched = true
					break
				}
			}
		}
		if matched {
			out = append(out, Finding{ID: r.id, Category: r.category,
				Name: r.name, Severity: r.severity, Engine: "heuristic"})
		}
	}
	return out
}
