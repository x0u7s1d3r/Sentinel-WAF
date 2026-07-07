// Package notifier envoie des alertes agrégées vers des webhooks de messagerie
// (Slack et/ou Discord) quand le WAF traite des attaques. Trois principes :
//
//  1. Anti-spam : les alertes sont AGRÉGÉES sur une fenêtre de temps. Un
//     scanner qui envoie 500 requêtes ne produit pas 500 messages, mais un
//     seul résumé « 500 attaques bloquées, dont … ».
//  2. Multi-destination : Slack et Discord peuvent être configurés ensemble ou
//     séparément ; chaque lot est envoyé à toutes les destinations actives.
//  3. Non bloquant et sûr : l'envoi se fait en arrière-plan ; si une messagerie
//     est indisponible, le trafic n'est jamais ralenti. Les webhooks sont des
//     secrets — ils n'apparaissent jamais dans le code.
package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Kinds de destinations supportées.
const (
	KindSlack   = "slack"
	KindDiscord = "discord"
)

// Alert décrit une attaque à signaler.
type Alert struct {
	App        string
	ClientIP   string
	Path       string
	Verdict    string // blocked | detected
	Categories []string
}

// Notifier agrège les alertes et les diffuse vers les webhooks configurés.
// Les webhooks sont modifiables à chaud (depuis le dashboard) : le notificateur
// tourne toujours, et n'envoie que vers les destinations effectivement définies.
// AnalyzeFunc produit une analyse en langage naturel d'un épisode d'attaques.
// Fournie par le module d'enrichissement (peut être nil = pas d'IA).
type AnalyzeFunc func(count, blocked, detected int, window, apps, cats, ips, paths string) (string, error)

// SaveAnalysisFunc persiste la dernière analyse (pour l'afficher au dashboard).
type SaveAnalysisFunc func(text string)

type Notifier struct {
	mu           sync.RWMutex
	slackURL     string
	discordURL   string
	interval     time.Duration
	ch           chan Alert
	quit         chan struct{}
	log          *slog.Logger
	client       *http.Client
	analyze      AnalyzeFunc
	saveAnalysis SaveAnalysisFunc
}

// SetEnricher branche l'analyse IA (appelée en arrière-plan, hors trafic).
func (n *Notifier) SetEnricher(analyze AnalyzeFunc, save SaveAnalysisFunc) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.analyze = analyze
	n.saveAnalysis = save
	n.mu.Unlock()
}

// New crée le notificateur. Il tourne toujours (même sans webhook) ; sans
// destination configurée, les envois sont simplement ignorés.
func New(slackURL, discordURL string, interval time.Duration, log *slog.Logger) *Notifier {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	n := &Notifier{
		slackURL:   slackURL,
		discordURL: discordURL,
		interval:   interval,
		ch:         make(chan Alert, 2048),
		quit:       make(chan struct{}),
		log:        log,
		client:     &http.Client{Timeout: 5 * time.Second},
	}
	go n.worker()
	return n
}

// SetWebhook change à chaud le webhook d'une destination (vide = désactive).
func (n *Notifier) SetWebhook(kind, url string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	switch kind {
	case KindDiscord:
		n.discordURL = url
	default:
		n.slackURL = url
	}
	n.mu.Unlock()
}

// Configured indique si une destination donnée a un webhook défini.
func (n *Notifier) Configured(kind string) bool {
	if n == nil {
		return false
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if kind == KindDiscord {
		return n.discordURL != ""
	}
	return n.slackURL != ""
}

func (n *Notifier) urlFor(kind string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if kind == KindDiscord {
		return n.discordURL
	}
	return n.slackURL
}

// Test envoie immédiatement un message de vérification à la destination donnée.
func (n *Notifier) Test(kind string) error {
	if n == nil {
		return fmt.Errorf("notificateur indisponible")
	}
	url := n.urlFor(kind)
	if url == "" {
		return fmt.Errorf("aucun webhook %s configuré", kind)
	}
	return n.post(kind, url, "🛡️ Sentinel WAF — message de test. Les alertes sont bien configurées ✅")
}

// post envoie un texte au webhook, au format attendu par la plateforme.
func (n *Notifier) post(kind, url, text string) error {
	var payload []byte
	if kind == KindDiscord {
		payload, _ = json.Marshal(map[string]string{"content": text}) // Discord
	} else {
		payload, _ = json.Marshal(map[string]string{"text": text}) // Slack
	}
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s a répondu HTTP %d", kind, resp.StatusCode)
	}
	return nil
}

// postJSON envoie un payload structuré déjà propre à la plateforme (embed
// Discord, attachment Slack) au webhook.
func (n *Notifier) postJSON(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook a répondu HTTP %d", resp.StatusCode)
	}
	return nil
}
func (n *Notifier) Notify(a Alert) {
	if n == nil {
		return
	}
	select {
	case n.ch <- a:
	default: // file saturée : on préfère perdre une alerte que bloquer le trafic
	}
}

func (n *Notifier) worker() {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()

	var pending []Alert
	drain := func() {
		for {
			select {
			case a := <-n.ch:
				pending = append(pending, a)
			default:
				return
			}
		}
	}

	for {
		select {
		case a := <-n.ch:
			pending = append(pending, a)
			if len(pending) >= 200 {
				drain()
				n.flush(pending)
				pending = nil
			}
		case <-ticker.C:
			drain()
			if len(pending) > 0 {
				n.flush(pending)
				pending = nil
			}
		case <-n.quit:
			drain()
			if len(pending) > 0 {
				n.flush(pending)
			}
			return
		}
	}
}

// flush construit un message de synthèse et l'envoie à toutes les destinations.
func (n *Notifier) flush(alerts []Alert) {
	slackURL := n.urlFor(KindSlack)
	discordURL := n.urlFor(KindDiscord)
	if slackURL == "" && discordURL == "" {
		return // aucune destination : on abandonne silencieusement le lot
	}

	blocked, detected := 0, 0
	byCat := map[string]int{}
	byIP := map[string]int{}
	byPath := map[string]int{}
	byApp := map[string]int{}
	for _, a := range alerts {
		if a.Verdict == "blocked" {
			blocked++
		} else {
			detected++
		}
		for _, c := range a.Categories {
			byCat[c]++
		}
		byIP[a.ClientIP]++
		if a.Path != "" {
			byPath[a.Path]++
		}
		if a.App != "" {
			byApp[a.App]++
		}
	}

	sev := severityFor(byCat, blocked)
	window := n.interval.String()
	apps := topCounts(byApp, 5)
	cats := topCounts(byCat, 6)
	ips := topCounts(byIP, 5)
	paths := topCounts(byPath, 5)
	verdict := fmt.Sprintf("%d bloquée(s) · %d surveillance", blocked, detected)
	when := time.Now().UTC().Format(time.RFC3339)

	// Analyse IA de l'épisode (en arrière-plan, hors chemin des requêtes).
	// En cas d'absence/erreur/lenteur, on continue sans analyse.
	analysis := ""
	n.mu.RLock()
	analyze, saveAnalysis := n.analyze, n.saveAnalysis
	n.mu.RUnlock()
	if analyze != nil {
		if txt, err := analyze(len(alerts), blocked, detected, window, apps, cats, ips, paths); err != nil {
			n.log.Warn("analyse IA indisponible", "err", err)
		} else if txt != "" {
			analysis = txt
			if saveAnalysis != nil {
				saveAnalysis(txt)
			}
		}
	}

	// Repli texte (utilisé si la plateforme ignore le format riche).
	fallback := fmt.Sprintf("🛡️ Sentinel WAF — %d attaque(s) en %s | Gravité %s | %s",
		len(alerts), window, sev.label, verdict)

	if slackURL != "" {
		payload := buildSlackPayload(sev, len(alerts), window, verdict, apps, cats, ips, paths, analysis, fallback)
		if err := n.postJSON(slackURL, payload); err != nil {
			n.log.Warn("envoi alerte Slack échoué", "err", err)
		}
	}
	if discordURL != "" {
		payload := buildDiscordPayload(sev, len(alerts), window, verdict, apps, cats, ips, paths, analysis, when)
		if err := n.postJSON(discordURL, payload); err != nil {
			n.log.Warn("envoi alerte Discord échoué", "err", err)
		}
	}
}

// severity décrit le niveau de gravité et ses couleurs par plateforme.
type severity struct {
	label        string
	discordColor int    // couleur décimale (embed Discord)
	slackColor   string // couleur hex (attachment Slack)
	emoji        string
}

// severityFor déduit la gravité des catégories vues et du nombre de blocages.
func severityFor(byCat map[string]int, blocked int) severity {
	high := map[string]bool{
		"sqli": true, "cmd_injection": true, "brute_force": true,
		"ssrf": true, "sensitive_path": true,
	}
	critical := false
	for c := range byCat {
		if high[c] {
			critical = true
			break
		}
	}
	switch {
	case critical && blocked > 0:
		return severity{"ÉLEVÉE", 0xE23D43, "#E23D43", "🔴"}
	case blocked > 0:
		return severity{"MODÉRÉE", 0xD9820A, "#D9820A", "🟠"}
	default:
		return severity{"SURVEILLANCE", 0xEAB308, "#EAB308", "🟡"}
	}
}

// buildDiscordPayload construit un embed Discord coloré.
func buildDiscordPayload(sev severity, count int, window, verdict, apps, cats, ips, paths, analysis, when string) map[string]any {
	fields := []map[string]any{
		{"name": "Gravité", "value": sev.emoji + " " + sev.label, "inline": true},
		{"name": "Fenêtre", "value": window, "inline": true},
	}
	if apps != "" {
		fields = append(fields, map[string]any{"name": "🎯 Application(s) visée(s)", "value": apps, "inline": false})
	}
	fields = append(fields, map[string]any{"name": "Verdict", "value": verdict, "inline": false})
	if cats != "" {
		fields = append(fields, map[string]any{"name": "Catégories", "value": cats, "inline": true})
	}
	if ips != "" {
		fields = append(fields, map[string]any{"name": "Sources (IP)", "value": ips, "inline": true})
	}
	if paths != "" {
		fields = append(fields, map[string]any{"name": "Cibles", "value": paths, "inline": false})
	}
	if analysis != "" {
		fields = append(fields, map[string]any{"name": "🧠 Analyse IA", "value": truncate(analysis, 1000), "inline": false})
	}
	return map[string]any{
		"embeds": []map[string]any{{
			"title":     fmt.Sprintf("🛡️ Sentinel WAF — %d attaque(s) détectée(s)", count),
			"color":     sev.discordColor,
			"fields":    fields,
			"footer":    map[string]any{"text": "Sentinel WAF"},
			"timestamp": when,
		}},
	}
}

// buildSlackPayload construit un attachment Slack coloré.
func buildSlackPayload(sev severity, count int, window, verdict, apps, cats, ips, paths, analysis, fallback string) map[string]any {
	fields := []map[string]any{
		{"title": "Gravité", "value": sev.emoji + " " + sev.label, "short": true},
		{"title": "Fenêtre", "value": window, "short": true},
	}
	if apps != "" {
		fields = append(fields, map[string]any{"title": "🎯 Application(s) visée(s)", "value": apps, "short": false})
	}
	fields = append(fields, map[string]any{"title": "Verdict", "value": verdict, "short": false})
	if cats != "" {
		fields = append(fields, map[string]any{"title": "Catégories", "value": cats, "short": true})
	}
	if ips != "" {
		fields = append(fields, map[string]any{"title": "Sources (IP)", "value": ips, "short": true})
	}
	if paths != "" {
		fields = append(fields, map[string]any{"title": "Cibles", "value": paths, "short": false})
	}
	if analysis != "" {
		fields = append(fields, map[string]any{"title": "🧠 Analyse IA", "value": truncate(analysis, 1500), "short": false})
	}
	return map[string]any{
		"text": fallback,
		"attachments": []map[string]any{{
			"color":  sev.slackColor,
			"title":  fmt.Sprintf("🛡️ Sentinel WAF — %d attaque(s) détectée(s)", count),
			"fields": fields,
			"footer": "Sentinel WAF",
			"ts":     time.Now().Unix(),
		}},
	}
}

// truncate borne une chaîne (limites de taille des embeds/attachments).
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// Close vide la file restante et arrête le worker.
func (n *Notifier) Close() {
	if n == nil {
		return
	}
	close(n.quit)
	time.Sleep(200 * time.Millisecond)
}

// topCounts renvoie "clé (n), clé (n)…" trié par fréquence décroissante.
func topCounts(m map[string]int, limit int) string {
	type kv struct {
		k string
		n int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].n > arr[j].n })
	out := ""
	for i, e := range arr {
		if i >= limit {
			break
		}
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s (%d)", e.k, e.n)
	}
	return out
}
