// Package detector définit le contrat commun à tous les moteurs de détection
// (sémantiques ou heuristiques) et la chaîne qui les agrège.
//
// Un WAF moderne combine plusieurs moteurs. Chacun implémente Detector et
// renvoie des Findings ; la Chain additionne les scores et agrège les
// catégories. La décision finale (bloquer / laisser passer) est prise en
// aval par le moteur de décision, en fonction du mode et du seuil.
package detector

// Request est la représentation normalisée d'une requête HTTP, telle que
// produite par le package parser. Les moteurs n'inspectent que ceci.
type Request struct {
	Method    string
	Path      string
	UserAgent string
	// Values regroupe toutes les valeurs à inspecter, déjà décodées :
	// valeurs et clés des paramètres de query, du corps, et le chemin.
	Values []string
}

// Finding décrit une détection unitaire.
type Finding struct {
	ID          string `json:"id"`          // ex. SEM-SQL-UNION
	Category    string `json:"category"`    // sqli, xss, ...
	Name        string `json:"name"`        // description lisible
	Severity    int    `json:"severity"`    // contribution au score
	Engine      string `json:"engine"`      // "semantic" | "heuristic"
}

// Result agrège les détections d'un ou plusieurs moteurs.
type Result struct {
	Findings   []Finding `json:"findings"`
	Categories []string  `json:"categories"`
	Score      int       `json:"score"`
}

// Detector est le contrat que tout moteur doit respecter.
type Detector interface {
	// Name identifie le moteur (pour les logs/plugins).
	Name() string
	// Inspect analyse la requête normalisée et renvoie les détections.
	Inspect(req Request) []Finding
}

// Chain exécute plusieurs détecteurs sur une requête et agrège le résultat
// (findings dédoublonnés par ID, score cumulé, catégories).
type Chain struct {
	detectors []Detector
}

// NewChain assemble une chaîne de détecteurs.
func NewChain(d ...Detector) *Chain {
	return &Chain{detectors: d}
}

// Inspect fait tourner toute la chaîne sur une requête normalisée.
func (c *Chain) Inspect(req Request) Result {
	seen := map[string]Finding{}
	for _, det := range c.detectors {
		for _, f := range det.Inspect(req) {
			if _, ok := seen[f.ID]; !ok {
				seen[f.ID] = f
			}
		}
	}

	findings := make([]Finding, 0, len(seen))
	catset := map[string]struct{}{}
	score := 0
	for _, f := range seen {
		findings = append(findings, f)
		catset[f.Category] = struct{}{}
		score += f.Severity
	}
	cats := make([]string, 0, len(catset))
	for c := range catset {
		cats = append(cats, c)
	}
	return Result{Findings: findings, Categories: cats, Score: score}
}
