// Commande gateway : la passerelle Sentinel WAF.
//
// Elle écoute le trafic entrant, l'inspecte via la chaîne de moteurs de
// détection, journalise l'événement (PostgreSQL si configuré), puis bloque ou
// transmet au backend protégé. Endpoints de supervision sous /_sentinel/.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-waf/internal/config"
	"sentinel-waf/internal/detector"
	"sentinel-waf/internal/proxy"
	"sentinel-waf/internal/storage"
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

	// Persistance : on tente d'ouvrir la base si un DSN est fourni. Si elle
	// n'est pas joignable, le WAF démarre quand même (sans persistance) —
	// la protection ne dépend jamais de la base.
	var store *storage.Store
	if cfg.Database != "" {
		store = openStoreWithRetry(cfg.Database, log)
	} else {
		log.Info("aucune base configurée : persistance désactivée")
	}
	defer func() {
		if store != nil {
			_ = store.Close()
		}
	}()

	// Chaîne de détection : moteurs sémantiques (SQL, XSS) + heuristiques.
	chain := detector.NewChain(
		detector.SQLSemantic{},
		detector.XSSSemantic{},
		detector.NewHeuristics(),
	)

	gw, err := proxy.New(cfg, chain, log, store)
	if err != nil {
		log.Error("initialisation passerelle", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_sentinel/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status": "ok", "mode": cfg.Mode, "persistence": store != nil,
		})
	})
	mux.HandleFunc("/_sentinel/stats", func(w http.ResponseWriter, r *http.Request) {
		if store != nil {
			if s, err := store.Stats(); err == nil {
				writeJSON(w, s)
				return
			}
		}
		writeJSON(w, map[string]int64{
			"total":    gw.Stats.Total.Load(),
			"blocked":  gw.Stats.Blocked.Load(),
			"detected": gw.Stats.Detected.Load(),
			"allowed":  gw.Stats.Allowed.Load(),
		})
	})
	mux.HandleFunc("/_sentinel/events", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, map[string]any{"events": []any{}, "persistence": false})
			return
		}
		events, err := store.Recent(100)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"events": events})
	})
	mux.Handle("/", gw)

	srv := &http.Server{Addr: cfg.Listen, Handler: mux}

	go func() {
		log.Info("Sentinel WAF — passerelle démarrée",
			"listen", cfg.Listen, "upstream", cfg.Upstream, "mode", cfg.Mode,
			"threshold", cfg.Threshold, "persistence", store != nil)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("serveur arrêté", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("arrêt en cours…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func openStoreWithRetry(dsn string, log *slog.Logger) *storage.Store {
	for i := 1; i <= 10; i++ {
		store, err := storage.Open(dsn)
		if err == nil {
			log.Info("base connectée, persistance active")
			return store
		}
		log.Warn("base injoignable, nouvelle tentative", "essai", i, "err", err)
		time.Sleep(2 * time.Second)
	}
	log.Warn("base toujours injoignable : démarrage SANS persistance")
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
