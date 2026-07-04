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
}
