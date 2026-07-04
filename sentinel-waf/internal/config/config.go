// Package config charge la configuration de la passerelle depuis un fichier
// JSON. On reste en JSON (bibliothèque standard) pour ne dépendre d'aucun
// module externe à ce stade — YAML viendra avec la couche de configuration
// avancée si besoin.
package config

import (
	"encoding/json"
	"os"
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

// Load lit un fichier JSON ; en cas d'absence, renvoie la config par défaut.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 4
	}
	if cfg.Mode == "" {
		cfg.Mode = "block"
	}
	return cfg, nil
}
