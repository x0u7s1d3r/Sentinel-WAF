package proxy

import (
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"sentinel-waf/internal/storage"
)

// Target est la cible retenue pour une requête : le backend, la politique de
// l'application (mode + seuil), et le reverse proxy prêt à l'emploi.
type Target struct {
	App storage.App
	rp  *httputil.ReverseProxy
}

// Router associe un domaine (en-tête Host) à une application enregistrée.
// Il est rechargé à chaud depuis la base : ajouter une application via l'API
// met la table à jour puis appelle Reload — aucun redémarrage nécessaire.
type Router struct {
	mu       sync.RWMutex
	byDomain map[string]*Target
}

// NewRouter crée un routeur vide.
func NewRouter() *Router {
	return &Router{byDomain: map[string]*Target{}}
}

// Reload reconstruit la table de routage à partir de la liste d'applications.
func (r *Router) Reload(apps []storage.App) {
	next := make(map[string]*Target, len(apps))
	for _, a := range apps {
		if a.Domain == "" {
			continue // une app sans domaine ne peut pas être routée par Host
		}
		target, err := url.Parse(a.UpstreamURL)
		if err != nil {
			continue // upstream invalide : on ignore cette entrée
		}
		rp := httputil.NewSingleHostReverseProxy(target)
		next[normalizeHost(a.Domain)] = &Target{App: a, rp: rp}
	}
	r.mu.Lock()
	r.byDomain = next
	r.mu.Unlock()
}

// Match cherche l'application correspondant à l'hôte de la requête.
func (r *Router) Match(host string) (*Target, bool) {
	h := normalizeHost(host)
	r.mu.RLock()
	t, ok := r.byDomain[h]
	r.mu.RUnlock()
	return t, ok
}

// Count renvoie le nombre d'applications routées (pour la supervision).
func (r *Router) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byDomain)
}

// normalizeHost retire le port et met en minuscules ("App.Tg:8080" -> "app.tg").
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
