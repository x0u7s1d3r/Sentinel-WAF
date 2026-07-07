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
	"time"
)

// Config regroupe les paramètres du fournisseur (fournis par l'environnement).
type Config struct {
	Enabled bool
	BaseURL string // ex : https://api.rodiumai.io/v1
	APIKey  string
	Model   string // ex : meta/llama-3.3-70b-instruct
}

// Client interroge l'API de complétion.
type Client struct {
	baseURL string
	apiKey  string
	model   string
	log     *slog.Logger
	http    *http.Client
}

// New crée le client, ou renvoie nil si l'enrichissement est désactivé ou mal
// configuré (auquel cas Enabled() renvoie false et aucun appel n'est fait).
func New(cfg Config, log *slog.Logger) *Client {
	if !cfg.Enabled || cfg.APIKey == "" || cfg.BaseURL == "" || cfg.Model == "" {
		return nil
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
		model:   cfg.Model,
		log:     log,
		http:    &http.Client{Timeout: 20 * time.Second},
	}
}

// Enabled indique si l'enrichissement est actif.
func (c *Client) Enabled() bool { return c != nil }

// Summary décrit un épisode d'attaques agrégé à analyser.
type Summary struct {
	Count      int
	Blocked    int
	Detected   int
	Window     string
	Categories string
	TopIPs     string
	TopPaths   string
}

const systemPrompt = `Tu es un analyste en cybersécurité (SOC) qui s'exprime en français.
On te fournit le résumé d'un épisode d'attaques détectées par un pare-feu applicatif web (WAF).
Rédige une analyse concise et professionnelle de 3 à 5 phrases, en prose (sans listes ni titres), comprenant :
la nature des attaques et l'intention probable de l'attaquant ; le niveau de risque ; une recommandation d'action concrète.
Reste factuel et précis. N'invente aucun détail absent du résumé.`

// Analyze renvoie l'analyse en langage naturel de l'épisode, ou une erreur.
func (c *Client) Analyze(ctx context.Context, s Summary) (string, error) {
	if c == nil {
		return "", fmt.Errorf("enrichissement désactivé")
	}
	user := fmt.Sprintf(
		"Épisode d'attaques (fenêtre : %s)\n- Total : %d (bloquées : %d, surveillance : %d)\n- Catégories : %s\n- Sources (IP) : %s\n- Cibles (URL) : %s",
		s.Window, s.Count, s.Blocked, s.Detected, orNone(s.Categories), orNone(s.TopIPs), orNone(s.TopPaths))

	payload := map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": user},
		},
		"max_tokens":  350,
		"temperature": 0.3,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

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

func orNone(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
