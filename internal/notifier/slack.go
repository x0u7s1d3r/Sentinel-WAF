// Package notifier envoie des alertes vers Slack quand le WAF traite des
// attaques. Deux principes :
//
//   1. Anti-spam : les alertes sont AGRÉGÉES sur une fenêtre de temps. Un
//      scanner qui envoie 500 requêtes ne produit pas 500 messages, mais un
//      seul résumé « 500 attaques bloquées, dont … ».
//   2. Non bloquant et sûr : l'envoi se fait en arrière-plan ; si Slack est
//      indisponible, le trafic n'est jamais ralenti. Le webhook est un secret
//      fourni par l'environnement — il n'apparaît jamais dans le code.
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

// Alert décrit une attaque à signaler.
type Alert struct {
	ClientIP   string
	Path       string
	Verdict    string // blocked | detected
	Categories []string
}

// Slack agrège et envoie les alertes à un webhook Slack (Incoming Webhook).
// Le webhook est modifiable à chaud (depuis le dashboard) : le notificateur
// existe toujours, et n'envoie que lorsqu'un webhook est configuré.
type Slack struct {
	mu       sync.RWMutex
	webhook  string
	interval time.Duration
	ch       chan Alert
	quit     chan struct{}
	log      *slog.Logger
	client   *http.Client
}

// NewSlack crée le notificateur. Il tourne toujours (même sans webhook) ; sans
// webhook configuré, les envois sont simplement ignorés.
func NewSlack(webhook string, interval time.Duration, log *slog.Logger) *Slack {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	s := &Slack{
		webhook:  webhook,
		interval: interval,
		ch:       make(chan Alert, 2048),
		quit:     make(chan struct{}),
		log:      log,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
	go s.worker()
	return s
}

// SetWebhook change le webhook à chaud (vide = désactive les alertes).
func (s *Slack) SetWebhook(url string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.webhook = url
	s.mu.Unlock()
}

// Configured indique si un webhook est actuellement défini.
func (s *Slack) Configured() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.webhook != ""
}

func (s *Slack) currentWebhook() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.webhook
}

// Test envoie immédiatement un message de vérification (hors agrégation).
// Renvoie une erreur si aucun webhook n'est configuré ou si l'envoi échoue.
func (s *Slack) Test() error {
	if s == nil {
		return fmt.Errorf("notificateur indisponible")
	}
	url := s.currentWebhook()
	if url == "" {
		return fmt.Errorf("aucun webhook Slack configuré")
	}
	return s.post(url, "🛡️ *Sentinel WAF* — message de test. Les alertes sont bien configurées ✅")
}

// post envoie un texte au webhook et renvoie une erreur en cas d'échec.
func (s *Slack) post(url, text string) error {
	payload, _ := json.Marshal(map[string]string{"text": text})
	resp, err := s.client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Slack a répondu HTTP %d", resp.StatusCode)
	}
	return nil
}

// Notify met une alerte en file sans bloquer (abandonnée si la file est pleine).
func (s *Slack) Notify(a Alert) {
	if s == nil {
		return
	}
	select {
	case s.ch <- a:
	default: // file saturée : on préfère perdre une alerte que bloquer le trafic
	}
}

func (s *Slack) worker() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	var pending []Alert
	drain := func() {
		for {
			select {
			case a := <-s.ch:
				pending = append(pending, a)
			default:
				return
			}
		}
	}

	for {
		select {
		case a := <-s.ch:
			pending = append(pending, a)
			// éviter une accumulation démesurée entre deux ticks
			if len(pending) >= 200 {
				drain()
				s.flush(pending)
				pending = nil
			}
		case <-ticker.C:
			drain()
			if len(pending) > 0 {
				s.flush(pending)
				pending = nil
			}
		case <-s.quit:
			drain()
			if len(pending) > 0 {
				s.flush(pending)
			}
			return
		}
	}
}

// flush construit un message de synthèse et l'envoie (ignoré si pas de webhook).
func (s *Slack) flush(alerts []Alert) {
	url := s.currentWebhook()
	if url == "" {
		return // aucun webhook : on abandonne silencieusement le lot
	}

	blocked, detected := 0, 0
	byCat := map[string]int{}
	byIP := map[string]int{}
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
	}

	text := fmt.Sprintf("🛡️ *Sentinel WAF* — %d attaque(s) détectée(s) (dernières %s)\n",
		len(alerts), s.interval)
	text += fmt.Sprintf("• Bloquées : %d · Laissées passer (surveillance) : %d\n", blocked, detected)
	if len(byCat) > 0 {
		text += "• Catégories : " + topCounts(byCat, 6) + "\n"
	}
	if len(byIP) > 0 {
		text += "• Top IP : " + topCounts(byIP, 5)
	}

	if err := s.post(url, text); err != nil {
		s.log.Warn("envoi alerte Slack échoué", "err", err)
	}
}

// Close vide la file restante et arrête le worker.
func (s *Slack) Close() {
	if s == nil {
		return
	}
	close(s.quit)
	time.Sleep(200 * time.Millisecond)
}

// topCounts renvoie "clé (n), clé (n)…" trié par fréquence décroissante.
func topCounts(m map[string]int, limit int) string {
	type kv struct {
		k string
		n int
	}
	var arr []kv
	for k, n := range m {
		arr = append(arr, kv{k, n})
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
