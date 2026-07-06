package detector

import "strings"

// SensitivePath repère les accès à des chemins notoirement sensibles : fichiers
// de secrets, panneaux d'administration, dépôts de code exposés, sauvegardes.
// C'est le tout premier geste d'un scanner (reconnaissance) — le détecter tôt
// permet de bloquer un attaquant avant même qu'il ne trouve une faille.
type SensitivePath struct{}

// Name identifie le moteur.
func (SensitivePath) Name() string { return "sensitive_path" }

// Motifs recherchés dans le chemin (comparaison en minuscules, sous-chaîne).
var sensitivePaths = []string{
	// secrets / configuration
	"/.env", "/.git", "/.svn", "/.hg", "/.aws", "/.ssh", "/.htaccess",
	"/config.php", "/configuration.php", "/wp-config", "/.npmrc", "/.dockercfg",
	// panneaux d'administration
	"/admin", "/administrator", "/wp-admin", "/wp-login", "/phpmyadmin",
	"/pma", "/adminer", "/manager/html", "/xmlrpc.php",
	// code / dépendances exposés
	"/vendor/", "/composer.json", "/composer.lock", "/package.json",
	"/.ds_store", "/server-status", "/actuator", "/cgi-bin/",
	// sauvegardes / dumps
	"/backup", "/backup.zip", "/db.sql", "/dump.sql", "/database.sql",
	"/.bak", "/.old", "/.swp",
}

// Inspect renvoie une détection si le chemin correspond à un motif sensible.
func (SensitivePath) Inspect(req Request) []Finding {
	p := strings.ToLower(req.Path)
	for _, s := range sensitivePaths {
		if strings.Contains(p, s) {
			return []Finding{{
				ID:       "HEUR-PATH" + strings.ToUpper(strings.ReplaceAll(s, "/", "-")),
				Category: "sensitive_path",
				Name:     "Accès à un chemin sensible (" + s + ")",
				Severity: 4,
				Engine:   "heuristic",
			}}
		}
	}
	return nil
}
