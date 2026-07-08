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
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := ":8080"
	if v := os.Getenv("LAB_LISTEN"); v != "" {
		addr = v
	}

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
		"Le paramètre est concaténé dans une requête SQL simulée sans échappement. Un payload d'injection modifie la logique de la requête.",
		[]string{"1' OR '1'='1", "1 UNION SELECT username,password FROM users", "admin'--"}},
	{"xss", "Cross-Site Scripting (XSS)", "xss",
		"La saisie est renvoyée telle quelle dans la page. Un script injecté s'exécuterait dans le navigateur de la victime.",
		[]string{"<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>", "<svg onload=alert(1)>"}},
	{"path", "Traversée de répertoire", "path_traversal",
		"Le nom de fichier demandé n'est pas filtré. Des séquences ../ permettent de sortir du dossier prévu.",
		[]string{"../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd"}},
	{"cmd", "Injection de commande", "cmd_injection",
		"La valeur est passée à une commande système simulée. Des métacaractères shell permettent d'enchaîner des commandes.",
		[]string{"127.0.0.1; cat /etc/passwd", "127.0.0.1 && whoami", "| id"}},
	{"ssrf", "Server-Side Request Forgery", "ssrf",
		"Le serveur récupère l'URL fournie. Un attaquant vise des ressources internes (métadonnées cloud, services locaux).",
		[]string{"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/", "file:///etc/passwd"}},
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
		"Un paramètre de page est inclus côté serveur. Il peut pointer vers des fichiers locaux sensibles.",
		[]string{"/etc/passwd", "php://filter/convert.base64-encode/resource=index", "../../../../etc/hosts"}},
	{"upload", "Upload de fichier", "bonus",
		"Le nom/type de fichier n'est pas validé. Un fichier exécutable pourrait être déposé.",
		[]string{"shell.php", "image.jpg.php", "../evil.sh"}},
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
		// Vulnérable : la saisie est injectée dans une requête SQL simulée.
		query := "SELECT * FROM products WHERE id = '" + id + "'"
		out := "Requête exécutée :\n" + html.EscapeString(query) + "\n\n"
		low := strings.ToLower(id)
		if strings.Contains(low, "union") && strings.Contains(low, "select") {
			out += "Résultat (simulé) :\nadmin | 5f4dcc3b5aa765d61d8327deb882cf99\nuser1 | 202cb962ac59075b964b07152d234b70\n\n⚠️ UNION SELECT interprété — extraction de données simulée."
			return v.Title, b + resultBox("Injection réussie (simulation)", out, true)
		}
		if strings.Contains(id, "'") || strings.Contains(low, " or ") || strings.Contains(id, "--") {
			out += "Résultat (simulé) :\nTOUS les produits retournés (condition toujours vraie).\n\n⚠️ La logique de la requête a été altérée par l'injection."
			return v.Title, b + resultBox("Injection réussie (simulation)", out, true)
		}
		out += "Résultat : 1 produit trouvé (comportement normal)."
		return v.Title, b + resultBox("Requête normale", out, false)
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
		if strings.Contains(file, "..") || strings.HasPrefix(file, "/etc") {
			content := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n(...) [contenu simulé de " + html.EscapeString(file) + "]"
			return v.Title, b + resultBox("Fichier hors périmètre lu (simulation)", content+"\n\n⚠️ Traversée de répertoire réussie.", true)
		}
		return v.Title, b + resultBox("Lecture normale", "Contenu du fichier autorisé : "+html.EscapeString(file), false)
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
		cmd := "ping -c 1 " + host
		out := "Commande exécutée :\n" + html.EscapeString(cmd) + "\n\n"
		if strings.ContainsAny(host, ";|&") || strings.Contains(host, "$(") {
			out += "PING 127.0.0.1 : 1 paquet\n\nroot:x:0:0:root:/root:/bin/bash\n(...) \n\n⚠️ Commande enchaînée exécutée — injection réussie (simulation)."
			return v.Title, b + resultBox("Injection de commande réussie (simulation)", out, true)
		}
		out += "PING " + html.EscapeString(host) + " : 1 paquet transmis (comportement normal)."
		return v.Title, b + resultBox("Commande normale", out, false)
	}
	return v.Title, b
}

func ssrfView(r *http.Request) (string, string) {
	v := vulnBySlug("ssrf")
	b := sectionHeader(v)
	u := r.URL.Query().Get("url")
	b += `<form method="GET" action="/ssrf" class="vform">
		<label>URL à récupérer côté serveur</label>
		<input type="text" name="url" placeholder="ex. http://169.254.169.254/latest/meta-data/" value="` + html.EscapeString(u) + `">
		<button type="submit">Récupérer</button></form>`
	if u != "" {
		low := strings.ToLower(u)
		if strings.Contains(low, "169.254.169.254") || strings.Contains(low, "127.0.0.1") || strings.Contains(low, "localhost") || strings.HasPrefix(low, "file:") {
			out := "Le serveur a tenté de récupérer : " + html.EscapeString(u) + "\n\n[réponse simulée]\niam-role: admin\naccess-key: AKIA...\n\n⚠️ Ressource interne atteinte — SSRF réussie (simulation)."
			return v.Title, b + resultBox("SSRF réussie (simulation)", out, true)
		}
		return v.Title, b + resultBox("Récupération externe normale", "Contenu récupéré depuis "+html.EscapeString(u)+" (comportement normal).", false)
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
		<label>Mot de passe</label>
		<input type="text" name="p" placeholder="password" value="` + html.EscapeString(p) + `">
		<button type="submit">Se connecter</button></form>
		<p class="hint2">Astuce : soumettez ce formulaire rapidement plusieurs fois de suite (8+ tentatives en 10 s) pour déclencher la détection de force brute du WAF.</p>`
	if u != "" || p != "" {
		if p == "letmein" {
			return v.Title, b + resultBox("Connexion réussie", "Bienvenue "+html.EscapeString(u)+" !", false)
		}
		return v.Title, b + resultBox("Échec de connexion", "Identifiants invalides. Réessayez.", true)
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
		if strings.Contains(pageParam, "/etc") || strings.Contains(pageParam, "..") || strings.HasPrefix(pageParam, "php://") {
			out := "include(\"" + html.EscapeString(pageParam) + "\")\n\nroot:x:0:0:root:/root:/bin/bash\n(...) [contenu local simulé]\n\n⚠️ Fichier local inclus — LFI réussie (simulation)."
			return v.Title, b + resultBox("Inclusion de fichier local réussie (simulation)", out, true)
		}
		return v.Title, b + resultBox("Inclusion normale", "Page incluse : "+html.EscapeString(pageParam), false)
	}
	return v.Title, b
}

func uploadView(r *http.Request) (string, string) {
	v := vulnBySlug("upload")
	b := sectionHeader(v)
	name := r.URL.Query().Get("filename")
	b += `<form method="GET" action="/upload" class="vform">
		<label>Nom du fichier à téléverser</label>
		<input type="text" name="filename" placeholder="ex. shell.php" value="` + html.EscapeString(name) + `">
		<button type="submit">Téléverser</button></form>`
	if name != "" {
		low := strings.ToLower(name)
		dangerous := []string{".php", ".sh", ".jsp", ".asp", ".exe", ".py"}
		for _, ext := range dangerous {
			if strings.Contains(low, ext) {
				out := "Fichier accepté : " + html.EscapeString(name) + "\nChemin : /uploads/" + html.EscapeString(name) + "\n\n⚠️ Extension exécutable acceptée — upload dangereux (simulation)."
				return v.Title, b + resultBox("Upload dangereux accepté (simulation)", out, true)
			}
		}
		return v.Title, b + resultBox("Upload normal", "Fichier "+html.EscapeString(name)+" accepté (type sûr).", false)
	}
	return v.Title, b
}

func csrfView(r *http.Request) (string, string) {
	v := vulnBySlug("csrf")
	b := sectionHeader(v)
	email := r.URL.Query().Get("email")
	b += `<p>Ce formulaire change l'email du compte <strong>sans jeton anti-CSRF ni vérification d'origine</strong>. Une page tierce pourrait le soumettre à votre insu.</p>
		<form method="GET" action="/csrf" class="vform">
		<label>Nouvel email du compte</label>
		<input type="text" name="email" placeholder="attaquant@evil.com" value="` + html.EscapeString(email) + `">
		<button type="submit">Changer l'email</button></form>`
	if email != "" {
		out := "Email du compte modifié en : " + html.EscapeString(email) + "\n\n⚠️ Action sensible exécutée sans jeton CSRF — vulnérable."
		return v.Title, b + resultBox("Action CSRF exécutée (simulation)", out, true)
	}
	return v.Title, b
}

func redirectView(r *http.Request) (string, string) {
	v := vulnBySlug("redirect")
	b := sectionHeader(v)
	to := r.URL.Query().Get("to")
	b += `<form method="GET" action="/redirect" class="vform">
		<label>Rediriger vers</label>
		<input type="text" name="to" placeholder="ex. //evil.example.com" value="` + html.EscapeString(to) + `">
		<button type="submit">Aller</button></form>`
	if to != "" {
		// Vulnérable : on n'effectue PAS la redirection réelle (sécurité du lab),
		// on montre juste que la cible n'est pas validée.
		safe := strings.HasPrefix(to, "/") && !strings.HasPrefix(to, "//") && !strings.HasPrefix(to, "/\\")
		if !safe {
			out := "Location: " + html.EscapeString(to) + "\n\n⚠️ Redirection vers un domaine externe non validé — redirection ouverte (simulation, non suivie)."
			return v.Title, b + resultBox("Redirection ouverte détectée (simulation)", out, true)
		}
		return v.Title, b + resultBox("Redirection interne normale", "Redirection vers "+html.EscapeString(to), false)
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
