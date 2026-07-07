// Package enricher produit une analyse d'attaque en langage naturel en
// interrogeant une API de complétion compatible OpenAI (RodiumAI, Groq, OpenAI,
// Ollama…). Deux principes :
//
//  1. HORS DU CHEMIN CRITIQUE : l'enrichissement est appelé en arrière-plan
//     (depuis le worker du notificateur), jamais pendant le traitement d'une
//     requête. Le trafic n'est donc jamais ralenti par le LLM.
//  2. DÉGRADATION GRACIEUSE : sans clé/URL/modèle, ou en cas d'erreur ou de
//     lenteur de l'API, l'analyse est simplement absente. Le WAF fonctionne
//     exactement comme sans LLM. La clé API est un secret (jamais journalisée).
package enricher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config regroupe les paramètres du fournisseur (fournis par l'environnement).
type Config struct {
	Enabled bool
	BaseURL string // ex : https://api.rodiumai.io/v1
	APIKey  string
	Model   string // ex : meta/llama-3.3-70b-instruct
}

// Client interroge l'API de complétion. Sa configuration est modifiable à chaud
// (depuis le dashboard), protégée par un mutex.
type Client struct {
	mu      sync.RWMutex
	enabled bool
	baseURL string
	apiKey  string
	model   string
	log     *slog.Logger
	http    *http.Client
}

// New crée le client (toujours non-nil). Il n'appelle l'API que si la
// configuration est complète et activée (voir Enabled).
func New(cfg Config, log *slog.Logger) *Client {
	c := &Client{log: log, http: &http.Client{Timeout: 20 * time.Second}}
	c.SetConfig(cfg)
	return c
}

// SetConfig applique une nouvelle configuration à chaud.
func (c *Client) SetConfig(cfg Config) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = cfg.Enabled && cfg.APIKey != "" && cfg.BaseURL != "" && cfg.Model != ""
	c.baseURL = strings.TrimRight(cfg.BaseURL, "/")
	c.apiKey = cfg.APIKey
	c.model = cfg.Model
}

// Enabled indique si l'enrichissement est actif et complètement configuré.
func (c *Client) Enabled() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// Summary décrit un épisode d'attaques agrégé à analyser.
type Summary struct {
	Count      int
	Blocked    int
	Detected   int
	Window     string
	Apps       string
	Categories string
	TopIPs     string
	TopPaths   string
}

const systemPrompt = `Tu es un analyste en cybersécurité (SOC) qui s'exprime en français.
On te fournit le résumé d'un épisode d'attaques détectées par un pare-feu applicatif web (WAF), avec l'application (le site) visée.
Réponds en deux parties nettes, en français, sans Markdown lourd :

ANALYSE : 2 à 3 phrases décrivant la nature des attaques, l'application ciblée, l'intention probable de l'attaquant et le niveau de risque.

MESURES IMMÉDIATES : 2 à 4 actions concrètes, courtes et directement applicables, séparées par des points-virgules (ex. « Bannir l'IP X depuis le dashboard ; auditer les journaux d'accès de l'application Y ; vérifier que les correctifs sont appliqués »). Les mesures doivent être précises et opérationnelles, pas génériques.

Reste factuel. N'invente aucun détail absent du résumé.`

// Analyze renvoie l'analyse en langage naturel de l'épisode, ou une erreur.
func (c *Client) Analyze(ctx context.Context, s Summary) (string, error) {
	if c == nil {
		return "", fmt.Errorf("enrichissement désactivé")
	}
	c.mu.RLock()
	enabled, baseURL, apiKey, model := c.enabled, c.baseURL, c.apiKey, c.model
	c.mu.RUnlock()
	if !enabled {
		return "", fmt.Errorf("enrichissement désactivé")
	}
	user := fmt.Sprintf(
		"Épisode d'attaques (fenêtre : %s)\n- Application(s) visée(s) : %s\n- Total : %d (bloquées : %d, surveillance : %d)\n- Catégories : %s\n- Sources (IP) : %s\n- Cibles (URL) : %s",
		s.Window, orNone(s.Apps), s.Count, s.Blocked, s.Detected, orNone(s.Categories), orNone(s.TopIPs), orNone(s.TopPaths))

	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": user},
		},
		"max_tokens":  350,
		"temperature": 0.3,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("API LLM a répondu HTTP %d", resp.StatusCode)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("réponse LLM vide")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

// Test vérifie la configuration en demandant une courte analyse d'exemple.
func (c *Client) Test(ctx context.Context) error {
	_, err := c.Analyze(ctx, Summary{
		Count: 1, Blocked: 1, Window: "test", Apps: "site-demo",
		Categories: "sqli (1)", TopIPs: "203.0.113.10 (1)", TopPaths: "/login (1)",
	})
	return err
}

func orNone(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
