package detector

import "testing"

func TestXSS(t *testing.T) {
	attacks := []string{
		"<script>alert(1)</script>",
		"<ScRiPt>alert(1)</ScRiPt>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"javascript:alert(1)",
		"\"><script>alert(document.cookie)</script>",
	}
	for _, a := range attacks {
		if score(scanXSS(a)) == 0 {
			t.Errorf("XSS NON DÉTECTÉ: %q", a)
		}
	}
	benign := []string{
		"1 < 2 and 3 > 4",
		"<3 you",
		"<b>gras</b>",
		"use a < b comparison",
		"email@domain.com",
		"prix < 100 EUR",
	}
	for _, b := range benign {
		if s := score(scanXSS(b)); s != 0 {
			t.Errorf("FAUX POSITIF XSS sur %q (score=%d)", b, s)
		}
	}
}

func TestHeuristics(t *testing.T) {
	h := NewHeuristics()
	// (valeur, doit-déclencher)
	cases := []struct {
		val string
		hit bool
	}{
		{"../../../../etc/passwd", true},
		{"127.0.0.1;cat /etc/passwd", true},
		{"http://169.254.169.254/latest/meta-data", true},
		{"http://127.0.0.1:8080/admin", true},
		{"file:///etc/passwd", true},
		{"$ne", true},
		{"/home/user/documents", false},
		{"recherche normale", false},
		{"https://example.com/page", false},
	}
	for _, c := range cases {
		req := Request{Values: []string{c.val}}
		got := score(h.Inspect(req)) > 0
		if got != c.hit {
			t.Errorf("heuristique %q : attendu hit=%v, obtenu %v", c.val, c.hit, got)
		}
	}
	// scanner via User-Agent
	req := Request{UserAgent: "sqlmap/1.7.2#stable"}
	if score(h.Inspect(req)) == 0 {
		t.Errorf("scanner sqlmap non détecté via User-Agent")
	}
}
