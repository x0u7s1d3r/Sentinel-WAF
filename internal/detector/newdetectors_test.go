package detector

import "testing"

func TestSensitivePath(t *testing.T) {
	d := SensitivePath{}
	// Chemins sensibles -> doivent être détectés.
	for _, p := range []string{"/.env", "/.git/config", "/wp-login.php", "/admin/", "/phpmyadmin/", "/backup.zip"} {
		if got := d.Inspect(Request{Path: p}); len(got) == 0 {
			t.Errorf("chemin sensible non détecté : %s", p)
		}
	}
	// Chemins légitimes -> ne doivent PAS être détectés.
	for _, p := range []string{"/", "/index.php", "/products/42", "/api/users", "/environment-page"} {
		if got := d.Inspect(Request{Path: p}); len(got) != 0 {
			t.Errorf("faux positif sur chemin légitime : %s (%v)", p, got)
		}
	}
}

func TestBruteForce(t *testing.T) {
	b := NewBruteForce()
	b.limit = 3 // seuil bas pour le test

	ip := "203.0.113.7"
	// 3 requêtes d'auth : sous le seuil, rien.
	for i := 0; i < 3; i++ {
		if got := b.Inspect(Request{Path: "/login", ClientIP: ip}); len(got) != 0 {
			t.Fatalf("détection prématurée à la requête %d", i+1)
		}
	}
	// La 4e dépasse le seuil -> détection.
	if got := b.Inspect(Request{Path: "/login", ClientIP: ip}); len(got) == 0 {
		t.Error("force brute non détectée au-delà du seuil")
	}

	// Une IP différente n'est pas affectée.
	if got := b.Inspect(Request{Path: "/login", ClientIP: "198.51.100.2"}); len(got) != 0 {
		t.Error("faux positif : une autre IP ne doit pas être signalée")
	}

	// Un chemin non-auth n'est jamais compté.
	for i := 0; i < 20; i++ {
		if got := b.Inspect(Request{Path: "/", ClientIP: ip}); len(got) != 0 {
			t.Fatal("faux positif : chemin non-auth signalé comme force brute")
		}
	}

	// Sans IP, pas de détection possible.
	if got := b.Inspect(Request{Path: "/login", ClientIP: ""}); len(got) != 0 {
		t.Error("détection sans IP : impossible, doit être ignorée")
	}
}
