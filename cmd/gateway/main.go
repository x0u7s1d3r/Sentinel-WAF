// Commande gateway : la passerelle Sentinel WAF.
//
// Elle écoute le trafic entrant, l'inspecte via la chaîne de moteurs de
// détection, puis bloque ou transmet au backend protégé. Endpoints de
// supervision sous /_sentinel/.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"

	"sentinel-waf/internal/config"
	"sentinel-waf/internal/detector"
	"sentinel-waf/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "configs/config.json", "chemin du fichier de configuration")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config invalide", "err", err)
		os.Exit(1)
	}

	// Chaîne de détection. Moteurs sémantiques (SQL, XSS) + couche heuristique
	// (traversée, commande, SSRF, NoSQL, scanner). Ajouter une protection =
	// ajouter un moteur ici, sans toucher au proxy ni au parser.
	chain := detector.NewChain(
		detector.SQLSemantic{},
		detector.XSSSemantic{},
		detector.NewHeuristics(),
	)

	gw, err := proxy.New(cfg, chain, log)
	if err != nil {
		log.Error("initialisation passerelle", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	// endpoints de supervision (préfixe réservé, non transmis au backend)
	mux.HandleFunc("/_sentinel/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "mode": cfg.Mode})
	})
	mux.HandleFunc("/_sentinel/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]int64{
			"total":    gw.Stats.Total.Load(),
			"blocked":  gw.Stats.Blocked.Load(),
			"detected": gw.Stats.Detected.Load(),
			"allowed":  gw.Stats.Allowed.Load(),
		})
	})
	// tout le reste passe par le pipeline WAF
	mux.Handle("/", gw)

	log.Info("Sentinel WAF — passerelle démarrée",
		"listen", cfg.Listen, "upstream", cfg.Upstream, "mode", cfg.Mode,
		"threshold", cfg.Threshold)

	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		log.Error("serveur arrêté", "err", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
