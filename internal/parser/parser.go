// Package parser transforme une *http.Request en detector.Request normalisée :
// il extrait, décode et regroupe toutes les valeurs à inspecter (paramètres de
// query, du corps, chemin), comme le fait un vrai WAF pour isoler chaque
// charge utile.
package parser

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"sentinel-waf/internal/detector"
)

// MaxBody borne la taille de corps lue pour l'inspection (évite l'abus mémoire).
const MaxBody = 1 << 20 // 1 Mo

// Parse lit la requête, en extrait les valeurs, et RESTITUE le corps lu afin
// que le proxy puisse encore le transmettre au backend.
func Parse(r *http.Request) (detector.Request, []byte) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, MaxBody))
		_ = r.Body.Close()
	}

	values := extractValues(r.URL, string(body))
	values = append(values, decode(r.URL.Path))

	return detector.Request{
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
		Values:    dedupe(values),
	}, body
}

// extractValues collecte les valeurs (et clés) des paramètres de query et du
// corps urlencodé ; sinon le corps brut (JSON, etc.).
//
// On ajoute TOUJOURS la query brute décodée dans son ensemble : Go abandonne
// silencieusement un paramètre dont la valeur contient un ';' (séparateur des
// injections de commande). Inspecter la query complète ferme cet angle mort.
func extractValues(u *url.URL, body string) []string {
	var vals []string

	if u.RawQuery != "" {
		vals = append(vals, decode(u.RawQuery))
	}

	for k, list := range u.Query() {
		vals = append(vals, decode(k))
		for _, v := range list {
			vals = append(vals, decode(v))
		}
	}

	if body != "" {
		if strings.Contains(body, "=") && (strings.Contains(body, "&") || strings.Count(body, "=") == 1) {
			if parsed, err := url.ParseQuery(body); err == nil {
				for k, list := range parsed {
					vals = append(vals, decode(k))
					for _, v := range list {
						vals = append(vals, decode(v))
					}
				}
			} else {
				vals = append(vals, decode(body))
			}
		} else {
			vals = append(vals, decode(body))
		}
	}
	return vals
}

// decode applique un double décodage d'URL pour contrer l'encodage d'évasion.
func decode(s string) string {
	if s == "" {
		return ""
	}
	once, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	twice, err := url.QueryUnescape(once)
	if err != nil {
		return once
	}
	return twice
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
