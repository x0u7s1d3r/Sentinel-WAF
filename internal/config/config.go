// Package config charge la configuration de la passerelle depuis un fichier
// JSON. On reste en JSON (bibliothèque standard) pour ne dépendre d'aucun
// module externe à ce stade — YAML viendra avec la couche de configuration
// avancée si besoin.
package config

import (
	"encoding/json"
	"os"
	"strconv"
)

type Config struct {
	// Adresse d'écoute de la passerelle, ex. ":8080"
	Listen string `json:"listen"`
	// URL du backend protégé, ex. "http://127.0.0.1:8000"
	Upstream string `json:"upstream"`
	// Mode de fonctionnement : "block" ou "detect"
	Mode string `json:"mode"`
	// Score à partir duquel une requête est bloquée (mode block)
	Threshold int `json:"threshold"`
	// DSN PostgreSQL, ex. "postgres://user:pass@host:5432/db?sslmode=disable"
	// Vide = pas de persistance (le WAF fonctionne quand même).
	Database string `json:"database"`
	// Webhook Slack pour les alertes. SECRET : à fournir par l'environnement
	// (SENTINEL_SLACK_WEBHOOK), jamais en dur dans un fichier versionné.
	SlackWebhook string `json:"-"`
	// Webhook Discord (SENTINEL_DISCORD_WEBHOOK), même principe que Slack.
	DiscordWebhook string `json:"-"`
	// Mot de passe admin initial. SECRET : fourni par l'environnement
	// (SENTINEL_ADMIN_PASSWORD). Sert à créer/réinitialiser le compte ; seul
	// son hachage est stocké, jamais le mot de passe en clair.
	AdminPassword string `json:"-"`
	// --- Enrichissement IA des alertes (facultatif) ---
	// API de complétion compatible OpenAI (RodiumAI, Groq, OpenAI, Ollama…).
	// La clé est un secret fourni par l'environnement, jamais versionné.
	LLMEnabled bool   `json:"-"`
	LLMBaseURL string `json:"-"`
	LLMAPIKey  string `json:"-"`
	LLMModel   string `json:"-"`
}

// Default fournit une configuration raisonnable si aucun fichier n'est fourni.
func Default() Config {
	return Config{
		Listen:    ":8080",
		Upstream:  "http://127.0.0.1:8000",
		Mode:      "block",
		Threshold: 4,
	}
}

// Load lit un fichier JSON puis applique les surcharges d'environnement.
// En l'absence de fichier, part de la config par défaut.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &cfg); err != nil {
				return cfg, err
			}
		case !os.IsNotExist(err):
			return cfg, err
		}
	}
	applyEnv(&cfg)
	if cfg.Threshold <= 0 {
		cfg.Threshold = 4
	}
	if cfg.Mode == "" {
		cfg.Mode = "block"
	}
	return cfg, nil
}

// applyEnv permet de surcharger la config sans reconstruire l'image (Docker).
func applyEnv(cfg *Config) {
	if v := os.Getenv("SENTINEL_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("SENTINEL_UPSTREAM"); v != "" {
		cfg.Upstream = v
	}
	if v := os.Getenv("SENTINEL_MODE"); v != "" {
		cfg.Mode = v
	}
	if v := os.Getenv("SENTINEL_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Threshold = n
		}
	}
	if v := os.Getenv("SENTINEL_DB_URL"); v != "" {
		cfg.Database = v
	}
	if v := os.Getenv("SENTINEL_SLACK_WEBHOOK"); v != "" {
		cfg.SlackWebhook = v
	}
	if v := os.Getenv("SENTINEL_DISCORD_WEBHOOK"); v != "" {
		cfg.DiscordWebhook = v
	}
	if v := os.Getenv("SENTINEL_ADMIN_PASSWORD"); v != "" {
		cfg.AdminPassword = v
	}
	if v := os.Getenv("LLM_ENABLED"); v == "true" || v == "1" {
		cfg.LLMEnabled = true
	}
	if v := os.Getenv("LLM_BASE_URL"); v != "" {
		cfg.LLMBaseURL = v
	}
	if v := os.Getenv("LLM_API_KEY"); v != "" {
		cfg.LLMAPIKey = v
	}
	if v := os.Getenv("LLM_MODEL"); v != "" {
		cfg.LLMModel = v
	}
}
