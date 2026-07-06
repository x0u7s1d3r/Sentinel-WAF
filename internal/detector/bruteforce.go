package detector

import (
	"strings"
	"sync"
	"time"
)

// BruteForce détecte le martèlement d'endpoints d'authentification : trop de
// requêtes depuis une même IP vers une page de login dans une courte fenêtre.
//
// Contrairement aux autres moteurs, il est À ÉTAT : il mémorise les horodatages
// récents par IP. Il est donc protégé pour l'accès concurrent (la passerelle
// traite les requêtes en parallèle) et purge périodiquement les vieilles entrées
// pour ne pas fuir en mémoire.
type BruteForce struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	hits   map[string][]int64 // IP -> horodatages (UnixNano) dans la fenêtre
	lastGC int64
}

// NewBruteForce crée le détecteur : au-delà de `limit` requêtes d'auth en
// `window`, l'IP est signalée. Valeurs par défaut : 8 requêtes en 10 s.
func NewBruteForce() *BruteForce {
	return &BruteForce{
		window: 10 * time.Second,
		limit:  8,
		hits:   map[string][]int64{},
	}
}

// Name identifie le moteur.
func (b *BruteForce) Name() string { return "brute_force" }

// isAuthPath cible les endpoints d'authentification (là où le brute-force a lieu).
func isAuthPath(p string) bool {
	p = strings.ToLower(p)
	for _, k := range []string{
		"login", "signin", "sign-in", "log-in", "auth", "wp-login.php",
		"/session", "/token", "/oauth", "/connexion",
	} {
		if strings.Contains(p, k) {
			return true
		}
	}
	return false
}

// Inspect enregistre la requête (si c'est une page d'auth) et signale l'IP
// lorsqu'elle dépasse le seuil dans la fenêtre glissante.
func (b *BruteForce) Inspect(req Request) []Finding {
	if req.ClientIP == "" || !isAuthPath(req.Path) {
		return nil
	}
	now := time.Now().UnixNano()
	cutoff := now - b.window.Nanoseconds()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Purge globale occasionnelle (au plus une fois par fenêtre) pour borner
	// la mémoire quand beaucoup d'IP différentes se présentent.
	if now-b.lastGC > b.window.Nanoseconds() {
		for ip, ts := range b.hits {
			if len(ts) == 0 || ts[len(ts)-1] < cutoff {
				delete(b.hits, ip)
			}
		}
		b.lastGC = now
	}

	// Élague les horodatages hors fenêtre pour cette IP, puis ajoute le courant.
	arr := b.hits[req.ClientIP]
	kept := arr[:0]
	for _, t := range arr {
		if t >= cutoff {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	b.hits[req.ClientIP] = kept

	if len(kept) > b.limit {
		return []Finding{{
			ID:       "HEUR-BRUTEFORCE",
			Category: "brute_force",
			Name:     "Tentatives d'authentification répétées (force brute)",
			Severity: 5,
			Engine:   "heuristic",
		}}
	}
	return nil
}
