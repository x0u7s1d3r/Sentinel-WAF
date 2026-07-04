package detector

import "regexp"

// XSSSemantic repère les CONSTRUCTIONS actives qu'une entrée introduit dans le
// HTML — balise exécutable, gestionnaire d'événement, pseudo-protocole
// javascript: — de façon robuste à la casse et aux espaces. Plus léger que le
// moteur SQL, mais dans le même esprit : on raisonne sur la structure, pas sur
// une chaîne fixe.
//
// Gains : "<ScRiPt>", "< script >", "<img src=x onerror=…>" sont vus ;
// "1 < 2 and 3 > 4", "<3", "<b>gras</b>" ne déclenchent PAS.
type XSSSemantic struct{}

func (XSSSemantic) Name() string { return "semantic-xss" }

var (
	dangerousTags = set("script", "svg", "iframe", "object", "embed",
		"applet", "meta", "base", "link", "form", "math", "template")
	tagWithHandler = set("img", "body", "video", "audio", "details",
		"marquee", "input", "select", "textarea", "a", "div", "style")

	reTag        = regexp.MustCompile(`(?i)<\s*/?\s*([a-z][a-z0-9]*)`)
	reHandler    = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
	reJSProto    = regexp.MustCompile(`(?i)(?:java|vb)script\s*:`)
	reDataHTML   = regexp.MustCompile(`(?i)data\s*:\s*text/html`)
	reAttrBreak  = regexp.MustCompile(`['"]\s*>`)
)

func scanXSS(value string) []Finding {
	if value == "" {
		return nil
	}
	var out []Finding
	add := func(id, name string, sev int) {
		out = append(out, Finding{ID: id, Category: "xss", Name: name,
			Severity: sev, Engine: "semantic"})
	}

	tags := map[string]bool{}
	for _, m := range reTag.FindAllStringSubmatch(value, -1) {
		tags[toLower(m[1])] = true
	}

	dangerous := ""
	for t := range tags {
		if dangerousTags[t] {
			dangerous = t
			break
		}
	}
	if dangerous != "" {
		add("SEM-XSS-TAG", "Balise active injectée : <"+dangerous+">", 5)
	}

	hasHandler := reHandler.MatchString(value)
	if hasHandler {
		add("SEM-XSS-HANDLER", "Gestionnaire d'événement JS (onerror/onload…)", 4)
	}

	// balise porteuse d'un gestionnaire d'événement (ex. <img ... onerror=>)
	if hasHandler && dangerous == "" {
		for t := range tags {
			if tagWithHandler[t] {
				add("SEM-XSS-IMGTAG", "Balise porteuse d'un gestionnaire d'événement", 4)
				break
			}
		}
	}

	if reJSProto.MatchString(value) {
		add("SEM-XSS-PROTO", "Pseudo-protocole javascript:/vbscript:", 4)
	}
	if reDataHTML.MatchString(value) {
		add("SEM-XSS-DATA", "URI data:text/html (exécution)", 4)
	}
	if reAttrBreak.MatchString(value) && (len(tags) > 0 || hasHandler) {
		add("SEM-XSS-BREAK", "Sortie de contexte d'attribut HTML", 3)
	}
	return out
}

// Inspect applique l'analyse XSS à toutes les valeurs de la requête.
func (XSSSemantic) Inspect(req Request) []Finding {
	var out []Finding
	for _, v := range req.Values {
		out = append(out, scanXSS(v)...)
	}
	return out
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
