// Attack Lab — application volontairement vulnérable pour tester Sentinel WAF.
//
// AVERTISSEMENT : ce service est INTENTIONNELLEMENT vulnérable. Il ne doit
// JAMAIS être exposé sur Internet ni déployé hors d'un environnement de test
// isolé. Son unique but est de fournir, façon DVWA, des pages où l'on saisit
// manuellement des charges (payloads) pour observer si le WAF les intercepte.
//
// Placé derrière Sentinel, soumettre un payload malveillant aboutit à :
//   - la page de blocage du WAF (requête interceptée), ou
//   - un comportement vulnérable réel de cette appli (payload passé).
//
// Aucune dépendance externe : bibliothèque standard uniquement.
package main

import (
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	addr := ":8080"
	if v := os.Getenv("LAB_LISTEN"); v != "" {
		addr = v
	}

	initDB() // vraie base SQLite en mémoire, pré-remplie

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/sqli", page(sqliView))
	mux.HandleFunc("/xss", page(xssView))
	mux.HandleFunc("/path", page(pathView))
	mux.HandleFunc("/cmd", page(cmdView))
	mux.HandleFunc("/ssrf", page(ssrfView))
	mux.HandleFunc("/nosql", page(nosqlView))
	mux.HandleFunc("/sensitive", page(sensitiveView))
	mux.HandleFunc("/bruteforce", page(bruteView))
	mux.HandleFunc("/lfi", page(lfiView))
	mux.HandleFunc("/upload", page(uploadView))
	mux.HandleFunc("/csrf", page(csrfView))
	mux.HandleFunc("/redirect", page(redirectView))
	// Chemins sensibles réellement exposés (pour tester la famille sensitive_path).
	mux.HandleFunc("/.env", handleFakeEnv)
	mux.HandleFunc("/admin", handleFakeAdmin)

	log.Printf("Attack Lab (appli vulnérable de test) démarré sur %s", addr)
	log.Printf("AVERTISSEMENT : appli volontairement vulnérable — usage test isolé uniquement")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// ---------- Modèle de vulnérabilité ----------

type vuln struct {
	Slug     string
	Title    string
	Family   string // famille Sentinel correspondante (ou "bonus")
	Desc     string
	Payloads []string
}

var vulns = []vuln{
	{"sqli", "Injection SQL", "sqli",
		"Le paramètre est concaténé dans une VRAIE requête SQLite sans échappement. Une injection extrait de vraies données : comptes, mots de passe, cartes bancaires.",
		[]string{"1' OR '1'='1", "1' UNION SELECT id,username,password,email FROM users--", "1' UNION SELECT id,username,credit_card,role FROM users--", "1' UNION SELECT id,sender,body,recipient FROM messages WHERE private=1--"}},
	{"xss", "Cross-Site Scripting (XSS)", "xss",
		"La saisie est renvoyée telle quelle dans la page. Un script injecté s'exécuterait dans le navigateur de la victime.",
		[]string{"<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>", "<svg onload=alert(1)>"}},
	{"path", "Traversée de répertoire", "path_traversal",
		"Le nom de fichier est lu RÉELLEMENT sur le disque du conteneur, sans filtrage. Base légitime : /app/pages/ (essayez home.txt). Des séquences ../ lisent de vrais fichiers système.",
		[]string{"home.txt", "config.txt", "../../../../etc/passwd", "../../../../etc/hostname"}},
	{"cmd", "Injection de commande", "cmd_injection",
		"La valeur est passée à un VRAI shell (sh -c). Des métacaractères enchaînent des commandes réellement exécutées dans le conteneur.",
		[]string{"127.0.0.1", "127.0.0.1; cat /etc/passwd", "127.0.0.1; id", "127.0.0.1 && uname -a"}},
	{"ssrf", "Server-Side Request Forgery", "ssrf",
		"Le serveur exécute une VRAIE requête HTTP vers l'URL fournie. Vous pouvez atteindre les services internes du réseau Docker.",
		[]string{"http://gateway:8080/health", "http://dvwa:80/", "http://127.0.0.1:8080/", "http://postgres:5432/"}},
	{"nosql", "Injection NoSQL", "nosql",
		"Les paramètres alimentent une requête de type MongoDB. Des opérateurs ($ne, $gt) contournent l'authentification.",
		[]string{`{"$ne": null}`, `{"$gt": ""}`, "admin'||'1'=='1"}},
	{"sensitive", "Accès à un chemin sensible", "sensitive_path",
		"Certains fichiers/dossiers ne devraient jamais être accessibles (.env, .git, sauvegardes, panneaux d'admin).",
		[]string{"/.env", "/admin", "/.git/config"}},
	{"bruteforce", "Force brute (authentification)", "brute_force",
		"Un formulaire de connexion sans limitation permet d'essayer de nombreux mots de passe rapidement.",
		[]string{"répéter la soumission rapidement", "admin / admin", "admin / password"}},
	{"lfi", "Local File Inclusion (LFI)", "bonus",
		"Un paramètre de page est lu RÉELLEMENT côté serveur. Il peut pointer vers de vrais fichiers locaux sensibles.",
		[]string{"config.txt", "/etc/passwd", "../../../../etc/hostname", "/etc/os-release"}},
	{"upload", "Upload de fichier", "bonus",
		"Le nom et le type ne sont pas validés : le fichier est RÉELLEMENT écrit sur le disque du conteneur (/tmp/uploads).",
		[]string{"shell.php", "test.txt", "../evil.sh", "backdoor.jsp"}},
	{"csrf", "Cross-Site Request Forgery", "bonus",
		"Une action sensible ne vérifie pas l'origine de la requête ni de jeton anti-CSRF.",
		[]string{"changer l'email sans jeton", "transfert forcé", "modifier le mot de passe"}},
	{"redirect", "Redirection ouverte", "bonus",
		"Un paramètre de redirection non validé peut renvoyer la victime vers un site malveillant.",
		[]string{"//evil.example.com", "https://evil.example.com/phishing", "/\\evil.example.com"}},
}

func vulnBySlug(slug string) *vuln {
	for i := range vulns {
		if vulns[i].Slug == slug {
			return &vulns[i]
		}
	}
	return nil
}

// ---------- Rendu commun (mise en page + barre latérale) ----------

// page enveloppe une vue de section dans la mise en page commune.
func page(view func(*http.Request) (title, body string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		title, body := view(r)
		// Signal spécial : redirection réelle (redirection ouverte).
		if strings.HasPrefix(body, "__REDIRECT__") {
			target := strings.TrimPrefix(body, "__REDIRECT__")
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, layout(title, r.URL.Path, body))
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	var b strings.Builder
	b.WriteString(`<div class="hero"><h1>Attack Lab</h1><p>Terrain d'entraînement volontairement vulnérable pour éprouver Sentinel WAF. Choisissez une vulnérabilité, saisissez un payload, observez si le pare-feu l'intercepte ou si l'application réagit.</p></div>`)
	b.WriteString(`<div class="warn">⚠️ Application <strong>intentionnellement vulnérable</strong>. À n'utiliser que derrière le WAF, en environnement de test isolé. Ne jamais exposer sur Internet.</div>`)
	b.WriteString(`<div class="cards">`)
	for _, v := range vulns {
		tag := "Sentinel"
		if v.Family == "bonus" {
			tag = "Bonus"
		}
		fmt.Fprintf(&b, `<a class="vcard" href="/%s"><span class="vtag %s">%s</span><h3>%s</h3><p>%s</p></a>`,
			v.Slug, map[bool]string{true: "bonus", false: "core"}[v.Family == "bonus"], tag, html.EscapeString(v.Title), html.EscapeString(v.Desc))
	}
	b.WriteString(`</div>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, layout("Accueil", "/", b.String()))
}

// sectionHeader rend le bloc explicatif + exemples de payloads d'une section.
func sectionHeader(v *vuln) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<div class="explain"><h2>%s</h2><p>%s</p>`, html.EscapeString(v.Title), html.EscapeString(v.Desc))
	if len(v.Payloads) > 0 {
		b.WriteString(`<div class="payloads"><span class="plabel">Exemples à copier :</span><ul>`)
		for _, p := range v.Payloads {
			fmt.Fprintf(&b, `<li><code>%s</code></li>`, html.EscapeString(p))
		}
		b.WriteString(`</ul></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// resultBox affiche le résultat d'une soumission.
func resultBox(label, content string, vulnerable bool) string {
	cls := "res-neutral"
	if vulnerable {
		cls = "res-vuln"
	}
	return fmt.Sprintf(`<div class="result %s"><div class="res-h">%s</div><pre>%s</pre></div>`,
		cls, html.EscapeString(label), content)
}

// ---------- Vues des sections (comportements vulnérables) ----------

func sqliView(r *http.Request) (string, string) {
	v := vulnBySlug("sqli")
	b := sectionHeader(v)
	b += `<form method="GET" action="/sqli" class="vform">
		<label>Identifiant produit à rechercher</label>
		<input type="text" name="id" placeholder="ex. 1' OR '1'='1" value="` + html.EscapeString(r.URL.Query().Get("id")) + `">
		<button type="submit">Rechercher</button></form>`
	if id := r.URL.Query().Get("id"); id != "" {
		// VULNÉRABLE : la saisie est injectée dans une vraie requête SQLite.
		sqlText, result, hasRows, err := searchProducts(id)
		if err != nil {
			// Une erreur SQL révèle souvent une injection (syntaxe cassée).
			out := "Requête exécutée :\n" + html.EscapeString(sqlText) + "\n\nErreur SQL : " + html.EscapeString(err.Error()) +
				"\n\n⚠️ L'erreur SQL confirme que l'entrée n'est pas filtrée (injection possible)."
			return v.Title, b + resultBox("Erreur SQL (injection détectée)", out, true)
		}
		out := "Requête exécutée :\n" + html.EscapeString(sqlText) + "\n\nRésultat réel de la base :\n" + html.EscapeString(result)
		// Heuristique d'affichage : plusieurs lignes ou données hors produits = injection.
		low := strings.ToLower(id)
		vulnerable := hasRows && (strings.Contains(low, "union") || strings.Contains(low, " or ") ||
			strings.Contains(id, "'") || strings.Contains(id, "--"))
		label := "Requête normale"
		if vulnerable {
			label = "Injection SQL réussie — données extraites de la vraie base"
			out += "\n⚠️ Injection réussie : des données réelles ont été extraites."
		}
		return v.Title, b + resultBox(label, out, vulnerable)
	}
	return v.Title, b
}

func xssView(r *http.Request) (string, string) {
	v := vulnBySlug("xss")
	b := sectionHeader(v)
	name := r.URL.Query().Get("name")
	b += `<form method="GET" action="/xss" class="vform">
		<label>Votre nom (affiché tel quel)</label>
		<input type="text" name="name" placeholder="ex. <script>alert(1)</script>" value="` + html.EscapeString(name) + `">
		<button type="submit">Envoyer</button></form>`
	if name != "" {
		// Vulnérable : réflexion SANS échappement (XSS reflété réel).
		body := `<div class="xss-out">Bonjour, ` + name + ` !</div>`
		note := "La saisie est insérée dans la page sans échappement. Si un script s'exécute, l'application est vulnérable (payload passé le WAF)."
		return v.Title, b + `<div class="result res-vuln"><div class="res-h">Sortie réfléchie (non échappée)</div>` + body + `<p class="res-note">` + note + `</p></div>`
	}
	return v.Title, b
}

func pathView(r *http.Request) (string, string) {
	v := vulnBySlug("path")
	b := sectionHeader(v)
	file := r.URL.Query().Get("file")
	b += `<form method="GET" action="/path" class="vform">
		<label>Fichier à afficher</label>
		<input type="text" name="file" placeholder="ex. ../../../../etc/passwd" value="` + html.EscapeString(file) + `">
		<button type="submit">Afficher</button></form>`
	if file != "" {
		// VULNÉRABLE : le chemin est concaténé sans nettoyage, puis lu réellement.
		// Une séquence ../ sort du dossier /app/pages et lit un vrai fichier système.
		data, err := os.ReadFile("/app/pages/" + file)
		if err != nil {
			// Repli : chemin absolu direct (LFI classique type /etc/passwd).
			data, err = os.ReadFile(file)
		}
		if err != nil {
			return v.Title, b + resultBox("Fichier introuvable", "Impossible de lire « "+html.EscapeString(file)+" » :\n"+html.EscapeString(err.Error()), false)
		}
		vulnerable := strings.Contains(file, "..") || strings.HasPrefix(file, "/")
		label := "Contenu du fichier (lecture réelle)"
		if vulnerable {
			label = "Traversée de répertoire réussie — fichier réel hors périmètre"
		}
		return v.Title, b + resultBox(label, html.EscapeString(string(data)), vulnerable)
	}
	return v.Title, b
}

func cmdView(r *http.Request) (string, string) {
	v := vulnBySlug("cmd")
	b := sectionHeader(v)
	host := r.URL.Query().Get("host")
	b += `<form method="GET" action="/cmd" class="vform">
		<label>Hôte à pinguer</label>
		<input type="text" name="host" placeholder="ex. 127.0.0.1; cat /etc/passwd" value="` + html.EscapeString(host) + `">
		<button type="submit">Ping</button></form>`
	if host != "" {
		// VULNÉRABLE : l'entrée est passée telle quelle à sh -c. Des métacaractères
		// (; | && $()) enchaînent des commandes réellement exécutées.
		out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
		body := "Commande exécutée :\nsh -c \"ping -c 1 " + html.EscapeString(host) + "\"\n\n" + html.EscapeString(string(out))
		if err != nil && len(out) == 0 {
			body += "\n[erreur] " + html.EscapeString(err.Error())
		}
		vulnerable := strings.ContainsAny(host, ";|&") || strings.Contains(host, "$(") || strings.Contains(host, "`")
		label := "Ping (commande normale)"
		if vulnerable {
			label = "Injection de commande réussie — commande réellement exécutée"
		}
		return v.Title, b + resultBox(label, body, vulnerable)
	}
	return v.Title, b
}

func ssrfView(r *http.Request) (string, string) {
	v := vulnBySlug("ssrf")
	b := sectionHeader(v)
	u := r.URL.Query().Get("url")
	b += `<form method="GET" action="/ssrf" class="vform">
		<label>URL à récupérer côté serveur</label>
		<input type="text" name="url" placeholder="ex. http://gateway:8080/ ou http://dvwa:80/" value="` + html.EscapeString(u) + `">
		<button type="submit">Récupérer</button></form>`
	if u != "" {
		// VULNÉRABLE : le serveur récupère l'URL fournie sans aucune validation
		// (schéma, hôte interne…). Il peut atteindre des services internes.
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			return v.Title, b + resultBox("Requête échouée", "Le serveur a tenté de récupérer « "+html.EscapeString(u)+" » :\n"+html.EscapeString(err.Error()), false)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		out := fmt.Sprintf("HTTP %d %s\n\n%s", resp.StatusCode, resp.Status, string(body))
		low := strings.ToLower(u)
		vulnerable := strings.Contains(low, "127.0.0.1") || strings.Contains(low, "localhost") ||
			strings.Contains(low, "169.254") || strings.Contains(low, "gateway") ||
			strings.Contains(low, "dvwa") || strings.Contains(low, "postgres") || strings.HasPrefix(low, "file:")
		label := "Contenu récupéré (requête réelle)"
		if vulnerable {
			label = "SSRF réussie — service interne atteint depuis le serveur"
		}
		return v.Title, b + resultBox(label, "Le serveur a récupéré « "+html.EscapeString(u)+" » :\n\n"+html.EscapeString(out), vulnerable)
	}
	return v.Title, b
}

func nosqlView(r *http.Request) (string, string) {
	v := vulnBySlug("nosql")
	b := sectionHeader(v)
	user := r.URL.Query().Get("user")
	b += `<form method="GET" action="/nosql" class="vform">
		<label>Nom d'utilisateur (requête NoSQL)</label>
		<input type="text" name="user" placeholder='ex. {"$ne": null}' value="` + html.EscapeString(user) + `">
		<button type="submit">Se connecter</button></form>`
	if user != "" {
		q := `db.users.find({ "user": ` + user + ` })`
		out := "Requête exécutée :\n" + html.EscapeString(q) + "\n\n"
		if strings.Contains(user, "$ne") || strings.Contains(user, "$gt") || strings.Contains(user, "||") {
			out += "Résultat (simulé) : premier utilisateur retourné → connecté en tant qu'admin.\n\n⚠️ Opérateur NoSQL interprété — contournement d'authentification."
			return v.Title, b + resultBox("Injection NoSQL réussie (simulation)", out, true)
		}
		out += "Résultat : aucun utilisateur (comportement normal)."
		return v.Title, b + resultBox("Requête normale", out, false)
	}
	return v.Title, b
}

func sensitiveView(r *http.Request) (string, string) {
	v := vulnBySlug("sensitive")
	b := sectionHeader(v)
	b += `<p>Ces liens pointent vers des ressources qui ne devraient jamais être accessibles. Derrière le WAF, elles doivent être bloquées :</p>
		<div class="linkrow">
		<a class="btn" href="/.env">Ouvrir /.env</a>
		<a class="btn" href="/admin">Ouvrir /admin</a>
		<a class="btn" href="/.git/config">Ouvrir /.git/config</a>
		</div>`
	return v.Title, b
}

func bruteView(r *http.Request) (string, string) {
	v := vulnBySlug("bruteforce")
	b := sectionHeader(v)
	u := r.URL.Query().Get("u")
	p := r.URL.Query().Get("p")
	b += `<form method="GET" action="/bruteforce" class="vform">
		<label>Utilisateur</label>
		<input type="text" name="u" placeholder="admin" value="` + html.EscapeString(u) + `">
		<label>Mot de passe (haché MD5 ou injection)</label>
		<input type="text" name="p" placeholder="5f4dcc3b5aa765d61d8327deb882cf99" value="` + html.EscapeString(p) + `">
		<button type="submit">Se connecter</button></form>
		<p class="hint2">Astuce 1 : soumettez rapidement 8+ fois pour déclencher la détection de force brute du WAF. Astuce 2 : essayez une injection SQL dans le login, ex. <code>' OR '1'='1</code> comme mot de passe.</p>`
	if u != "" || p != "" {
		// VULNÉRABLE : login par concaténation directe (injectable).
		sqlText, result, ok, err := loginVulnerable(u, p)
		if err != nil {
			out := "Requête exécutée :\n" + html.EscapeString(sqlText) + "\n\nErreur SQL : " + html.EscapeString(err.Error())
			return v.Title, b + resultBox("Erreur SQL (injection détectée)", out, true)
		}
		if ok {
			out := "Requête exécutée :\n" + html.EscapeString(sqlText) + "\n\nAuthentifié ! Comptes correspondants :\n" + html.EscapeString(result)
			return v.Title, b + resultBox("Connexion réussie", out, strings.Contains(p, "'") || strings.Contains(p, " OR "))
		}
		out := "Requête exécutée :\n" + html.EscapeString(sqlText) + "\n\nIdentifiants invalides."
		return v.Title, b + resultBox("Échec de connexion", out, false)
	}
	return v.Title, b
}

func lfiView(r *http.Request) (string, string) {
	v := vulnBySlug("lfi")
	b := sectionHeader(v)
	pageParam := r.URL.Query().Get("page")
	b += `<form method="GET" action="/lfi" class="vform">
		<label>Page à inclure</label>
		<input type="text" name="page" placeholder="ex. /etc/passwd" value="` + html.EscapeString(pageParam) + `">
		<button type="submit">Inclure</button></form>`
	if pageParam != "" {
		// VULNÉRABLE : inclusion/lecture réelle du fichier demandé, sans filtrage.
		data, err := os.ReadFile("/app/pages/" + pageParam)
		if err != nil {
			data, err = os.ReadFile(pageParam)
		}
		if err != nil {
			return v.Title, b + resultBox("Inclusion échouée", "include(\""+html.EscapeString(pageParam)+"\") :\n"+html.EscapeString(err.Error()), false)
		}
		vulnerable := strings.Contains(pageParam, "..") || strings.HasPrefix(pageParam, "/")
		label := "Page incluse (lecture réelle)"
		if vulnerable {
			label = "Inclusion de fichier local réussie — fichier réel"
		}
		return v.Title, b + resultBox(label, "include(\""+html.EscapeString(pageParam)+"\") →\n\n"+html.EscapeString(string(data)), vulnerable)
	}
	return v.Title, b
}

func uploadView(r *http.Request) (string, string) {
	v := vulnBySlug("upload")
	b := sectionHeader(v)
	name := r.URL.Query().Get("filename")
	content := r.URL.Query().Get("content")
	b += `<form method="GET" action="/upload" class="vform">
		<label>Nom du fichier à téléverser</label>
		<input type="text" name="filename" placeholder="ex. shell.php" value="` + html.EscapeString(name) + `">
		<label>Contenu (facultatif)</label>
		<input type="text" name="content" placeholder="<?php system($_GET[c]); ?>" value="` + html.EscapeString(content) + `">
		<button type="submit">Téléverser</button></form>`
	if name != "" {
		if content == "" {
			content = "// fichier de test déposé par l'Attack Lab\n"
		}
		// VULNÉRABLE : nom non nettoyé (peut contenir ../), aucune vérif d'extension.
		// Le fichier est réellement écrit sur le disque du conteneur.
		dir := "/tmp/uploads"
		_ = os.MkdirAll(dir, 0o755)
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return v.Title, b + resultBox("Upload échoué", html.EscapeString(err.Error()), false)
		}
		entries, _ := os.ReadDir(dir)
		var sb strings.Builder
		fmt.Fprintf(&sb, "Fichier écrit sur le disque : %s\n\nContenu de %s :\n", full, dir)
		for _, e := range entries {
			info, _ := e.Info()
			var size int64
			if info != nil {
				size = info.Size()
			}
			fmt.Fprintf(&sb, "  %-30s %d octets\n", e.Name(), size)
		}
		low := strings.ToLower(name)
		dangerous := strings.Contains(name, "..")
		for _, ext := range []string{".php", ".sh", ".jsp", ".asp", ".exe", ".py"} {
			if strings.Contains(low, ext) {
				dangerous = true
				break
			}
		}
		label := "Fichier téléversé (écriture réelle)"
		if dangerous {
			label = "Upload dangereux accepté — fichier réellement écrit"
		}
		return v.Title, b + resultBox(label, html.EscapeString(sb.String()), dangerous)
	}
	return v.Title, b
}

func csrfView(r *http.Request) (string, string) {
	v := vulnBySlug("csrf")
	b := sectionHeader(v)
	email := r.URL.Query().Get("email")
	b += `<p>Ce formulaire change l'email du compte <strong>admin</strong> en base, <strong>sans jeton anti-CSRF ni vérification d'origine</strong>. Une page tierce pourrait le soumettre à votre insu.</p>
		<form method="GET" action="/csrf" class="vform">
		<label>Nouvel email du compte admin</label>
		<input type="text" name="email" placeholder="attaquant@evil.com" value="` + html.EscapeString(email) + `">
		<button type="submit">Changer l'email</button></form>`
	if email != "" {
		// RÉEL : modification effective en base, sans aucune protection CSRF.
		_, err := db.Exec("UPDATE users SET email = ? WHERE username = 'admin'")
		_ = err
		// On relit pour prouver le changement (requête vulnérable directe).
		_, res, _, _ := vulnerableQuery("SELECT username, email, role FROM users WHERE username='admin'")
		// Applique réellement la nouvelle valeur.
		db.Exec("UPDATE users SET email = '" + email + "' WHERE username = 'admin'")
		_, res2, _, _ := vulnerableQuery("SELECT username, email, role FROM users WHERE username='admin'")
		out := "Avant :\n" + res + "\nAprès (email réellement modifié) :\n" + res2 +
			"\n⚠️ Action sensible exécutée sans jeton CSRF."
		return v.Title, b + resultBox("Action CSRF exécutée — email réellement modifié en base", html.EscapeString(out), true)
	}
	return v.Title, b
}

func redirectView(r *http.Request) (string, string) {
	v := vulnBySlug("redirect")
	b := sectionHeader(v)
	to := r.URL.Query().Get("to")
	b += `<form method="GET" action="/redirect" class="vform">
		<label>Rediriger vers</label>
		<input type="text" name="to" placeholder="ex. https://evil.example.com" value="` + html.EscapeString(to) + `">
		<button type="submit">Aller</button></form>
		<p class="hint2">Note : avec le paramètre <code>&go=1</code>, la redirection est réellement effectuée (302). Sans lui, la cible est seulement affichée pour éviter de quitter le lab par erreur.</p>`
	if to != "" {
		unsafe := !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") || strings.HasPrefix(to, "/\\")
		if r.URL.Query().Get("go") == "1" && unsafe {
			// RÉEL : redirection ouverte effective vers une cible non validée.
			// (Le navigateur suivra ce Location.)
			return "", "__REDIRECT__" + to
		}
		if unsafe {
			out := "Location: " + html.EscapeString(to) + "\n\n⚠️ Cible externe non validée. Ajoutez &go=1 à l'URL pour effectuer réellement la redirection (redirection ouverte)."
			return v.Title, b + resultBox("Redirection ouverte détectée", out, true)
		}
		return v.Title, b + resultBox("Redirection interne normale", "Location: "+html.EscapeString(to), false)
	}
	return v.Title, b
}

// Chemins sensibles réellement servis (pour la famille sensitive_path).
func handleFakeEnv(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "# Ce fichier ne devrait jamais être accessible !\nDB_PASSWORD=super_secret\nAPI_KEY=sk-demo-1234567890\n")
}

func handleFakeAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, layout("Admin", "/admin", `<div class="result res-vuln"><div class="res-h">Panneau d'administration exposé</div><p>Ce panneau ne devrait jamais être accessible sans authentification. Derrière le WAF, l'accès à ce chemin doit être bloqué.</p></div>`))
}
