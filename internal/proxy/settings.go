package proxy

import (
	"sort"
	"sync"

	"sentinel-waf/internal/detector"
	"sentinel-waf/internal/storage"
)

// Settings porte la configuration MODIFIABLE À CHAUD du WAF : mode et seuil
// globaux, catégories de détection activées, et blocklist d'IP. L'état est
// protégé pour l'accès concurrent et persisté en base (survit au redémarrage).
type Settings struct {
	mu             sync.RWMutex
	mode           string
	threshold      int
	enabled        map[string]bool
	blocklist      map[string]bool
	slackWebhook   string
	discordWebhook string
	store          *storage.Store
}

// NewSettings initialise depuis la config, puis écrase avec l'état persisté
// s'il existe. Par défaut, toutes les catégories sont activées.
func NewSettings(mode string, threshold int, store *storage.Store) *Settings {
	s := &Settings{
		mode: mode, threshold: threshold,
		enabled:   map[string]bool{},
		blocklist: map[string]bool{},
		store:     store,
	}
	for cat := range detector.Categories {
		s.enabled[cat] = true
	}
	s.load()
	return s
}

func (s *Settings) load() {
	if s.store == nil {
		return
	}
	var mode string
	if ok, _ := s.store.LoadSetting("mode", &mode); ok && mode != "" {
		s.mode = mode
	}
	var thr int
	if ok, _ := s.store.LoadSetting("threshold", &thr); ok && thr > 0 {
		s.threshold = thr
	}
	// Modèle opt-out : toutes les catégories sont actives par défaut (initialisé
	// dans NewSettings) ; on ne persiste que celles EXPLICITEMENT désactivées.
	// Ainsi, toute nouvelle famille de détection ajoutée par la suite est active
	// d'office, sans être exclue par une ancienne liste enregistrée.
	var disabled []string
	if ok, _ := s.store.LoadSetting("disabled_categories", &disabled); ok {
		for _, c := range disabled {
			s.enabled[c] = false
		}
	}
	var bl []string
	if ok, _ := s.store.LoadSetting("blocklist", &bl); ok {
		s.blocklist = map[string]bool{}
		for _, ip := range bl {
			s.blocklist[ip] = true
		}
	}
	var wh string
	if ok, _ := s.store.LoadSetting("slack_webhook", &wh); ok {
		s.slackWebhook = wh
	}
	var dwh string
	if ok, _ := s.store.LoadSetting("discord_webhook", &dwh); ok {
		s.discordWebhook = dwh
	}
}

// ---- Lectures (chemin chaud, RLock) ----

func (s *Settings) Mode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

func (s *Settings) Threshold() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.threshold
}

func (s *Settings) Enabled(cat string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled[cat]
}

func (s *Settings) IsBlocked(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blocklist[ip]
}

// ---- Écritures (persistées) ----

func (s *Settings) SetMode(mode string) {
	if mode != "block" && mode != "detect" {
		return
	}
	s.mu.Lock()
	s.mode = mode
	s.mu.Unlock()
	_ = s.store.SaveSetting("mode", mode)
}

func (s *Settings) SetThreshold(n int) {
	if n < 1 {
		n = 1
	}
	s.mu.Lock()
	s.threshold = n
	s.mu.Unlock()
	_ = s.store.SaveSetting("threshold", n)
}

// SetCategories reçoit la liste des catégories ACTIVES (depuis l'UI) et persiste
// l'inverse : la liste des DÉSACTIVÉES. Toute catégorie absente des deux (une
// nouveauté future) reste active par défaut.
func (s *Settings) SetCategories(cats []string) {
	want := map[string]bool{}
	for _, c := range cats {
		if _, valid := detector.Categories[c]; valid {
			want[c] = true
		}
	}
	next := map[string]bool{}
	var disabled []string
	for cat := range detector.Categories {
		next[cat] = want[cat]
		if !want[cat] {
			disabled = append(disabled, cat)
		}
	}
	sort.Strings(disabled)
	s.mu.Lock()
	s.enabled = next
	s.mu.Unlock()
	_ = s.store.SaveSetting("disabled_categories", disabled)
}

func (s *Settings) Block(ip string)   { s.setBlock(ip, true) }
func (s *Settings) Unblock(ip string) { s.setBlock(ip, false) }

// SlackWebhook renvoie le webhook persisté (pour l'initialisation au démarrage).
func (s *Settings) SlackWebhook() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.slackWebhook
}

// SetSlackWebhook enregistre le webhook Slack (persisté).
func (s *Settings) SetSlackWebhook(url string) {
	s.mu.Lock()
	s.slackWebhook = url
	s.mu.Unlock()
	_ = s.store.SaveSetting("slack_webhook", url)
}

// DiscordWebhook renvoie le webhook Discord persisté.
func (s *Settings) DiscordWebhook() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.discordWebhook
}

// SetDiscordWebhook enregistre le webhook Discord (persisté).
func (s *Settings) SetDiscordWebhook(url string) {
	s.mu.Lock()
	s.discordWebhook = url
	s.mu.Unlock()
	_ = s.store.SaveSetting("discord_webhook", url)
}

func (s *Settings) setBlock(ip string, on bool) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	if on {
		s.blocklist[ip] = true
	} else {
		delete(s.blocklist, ip)
	}
	list := make([]string, 0, len(s.blocklist))
	for k := range s.blocklist {
		list = append(list, k)
	}
	s.mu.Unlock()
	sort.Strings(list)
	_ = s.store.SaveSetting("blocklist", list)
}

// Snapshot renvoie l'état complet pour l'API (lecture atomique).
func (s *Settings) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	en := make([]string, 0, len(s.enabled))
	for c := range s.enabled {
		en = append(en, c)
	}
	sort.Strings(en)
	bl := make([]string, 0, len(s.blocklist))
	for ip := range s.blocklist {
		bl = append(bl, ip)
	}
	sort.Strings(bl)
	return map[string]any{
		"mode":                s.mode,
		"threshold":           s.threshold,
		"enabled_categories":  en,
		"all_categories":      detector.Categories,
		"blocklist":           bl,
		"slack_webhook_set":   s.slackWebhook != "",
		"discord_webhook_set": s.discordWebhook != "",
	}
}
