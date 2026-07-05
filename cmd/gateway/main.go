// Commande gateway : la passerelle Sentinel WAF.
//
// Elle écoute le trafic entrant, l'inspecte via la chaîne de moteurs de
// détection, journalise l'événement (PostgreSQL si configuré), route vers la
// bonne application (par domaine) puis bloque ou transmet. Endpoints de
// supervision et de gestion sous /_sentinel/.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"sentinel-waf/internal/config"
	"sentinel-waf/internal/detector"
	"sentinel-waf/internal/notifier"
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

	// Persistance : le WAF démarre même si la base est indisponible.
	var store *storage.Store
	if cfg.Database != "" {
		store = openStoreWithRetry(cfg.Database, log)
	} else {
		log.Info("aucune base configurée : persistance et multi-app désactivés")
	}
	defer func() {
		if store != nil {
			_ = store.Close()
		}
	}()

	chain := detector.NewChain(
		detector.SQLSemantic{},
		detector.XSSSemantic{},
		detector.NewHeuristics(),
	)

	// Alertes Slack (facultatif) : actives seulement si un webhook est fourni
	// par l'environnement. Intervalle d'agrégation réglable (défaut 15 s).
	alertInterval := 15 * time.Second
	if v := os.Getenv("SENTINEL_ALERT_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			alertInterval = time.Duration(n) * time.Second
		}
	}
	notif := notifier.NewSlack(cfg.SlackWebhook, alertInterval, log)
	if notif != nil {
		log.Info("alertes Slack activées", "intervalle", alertInterval)
		defer notif.Close()
	}

	// Routeur multi-application : chargé depuis la base, rechargé à chaud.
	router := proxy.NewRouter()
	reloadRouter(store, router, log)
	if store != nil {
		go refreshLoop(store, router, log) // capte les changements externes
	}

	// Configuration modifiable à chaud (mode, seuil, catégories, blocklist),
	// initialisée depuis le fichier puis l'état persisté en base.
	settings := proxy.NewSettings(cfg.Mode, cfg.Threshold, store)

	gw, err := proxy.New(cfg, chain, log, store, router, notif, settings)
	if err != nil {
		log.Error("initialisation passerelle", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_sentinel/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status": "ok", "mode": settings.Mode(),
			"persistence": store != nil, "apps": router.Count(),
		})
	})
	mux.HandleFunc("/_sentinel/stats", func(w http.ResponseWriter, r *http.Request) {
		if store != nil {
			if s, err := store.Stats(r.URL.Query().Get("app")); err == nil {
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
		events, err := store.Recent(100, r.URL.Query().Get("app"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"events": events})
	})

	mux.HandleFunc("/_sentinel/analytics", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, map[string]any{"persistence": false})
			return
		}
		a, err := store.Analytics(r.URL.Query().Get("app"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, a)
	})

	// --- Configuration dynamique (mode, seuil, catégories) ---
	mux.HandleFunc("/_sentinel/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, settings.Snapshot())
		case http.MethodPost:
			var body struct {
				Mode              *string  `json:"mode"`
				Threshold         *int     `json:"threshold"`
				EnabledCategories *[]string `json:"enabled_categories"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "corps JSON invalide", http.StatusBadRequest)
				return
			}
			if body.Mode != nil {
				settings.SetMode(*body.Mode)
			}
			if body.Threshold != nil {
				settings.SetThreshold(*body.Threshold)
			}
			if body.EnabledCategories != nil {
				settings.SetCategories(*body.EnabledCategories)
			}
			writeJSON(w, settings.Snapshot())
		default:
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
		}
	})

	// --- Blocklist d'IP pilotable ---
	mux.HandleFunc("/_sentinel/blocklist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				IP     string `json:"ip"`
				Action string `json:"action"` // "add" | "remove"
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "corps JSON invalide", http.StatusBadRequest)
				return
			}
			if body.Action == "remove" {
				settings.Unblock(body.IP)
			} else {
				settings.Block(body.IP)
			}
		}
		writeJSON(w, map[string]any{"blocklist": settings.Snapshot()["blocklist"]})
	})

	// --- Gestion des applications surveillées (multi-app) ---
	mux.HandleFunc("/_sentinel/apps", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, "multi-app indisponible : configurez une base de données", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			apps, err := store.ListApps()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"apps": apps})

		case http.MethodPost:
			var a storage.App
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
				http.Error(w, "corps JSON invalide", http.StatusBadRequest)
				return
			}
			if a.Name == "" || a.Domain == "" || a.UpstreamURL == "" {
				http.Error(w, "name, domain et upstream_url sont requis", http.StatusBadRequest)
				return
			}
			created, err := store.AddApp(a)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reloadRouter(store, router, log)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, created)

		case http.MethodPut:
			var body struct {
				ID        int64  `json:"id"`
				Mode      string `json:"mode"`
				Threshold int    `json:"threshold"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == 0 {
				http.Error(w, "id, mode et threshold requis", http.StatusBadRequest)
				return
			}
			if err := store.UpdateApp(body.ID, body.Mode, body.Threshold); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reloadRouter(store, router, log)
			writeJSON(w, map[string]any{"updated": body.ID})

		case http.MethodDelete:
			id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
			if err != nil {
				http.Error(w, "paramètre id invalide", http.StatusBadRequest)
				return
			}
			if err := store.DeleteApp(id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reloadRouter(store, router, log)
			writeJSON(w, map[string]any{"deleted": id})

		default:
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
		}
	})

	mux.Handle("/", gw)

	srv := &http.Server{Addr: cfg.Listen, Handler: mux}
	go func() {
		log.Info("Sentinel WAF — passerelle démarrée",
			"listen", cfg.Listen, "upstream_defaut", cfg.Upstream, "mode", cfg.Mode,
			"threshold", cfg.Threshold, "persistence", store != nil, "apps", router.Count())
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

// reloadRouter recharge la table de routage depuis la base (sans effet si nil).
func reloadRouter(store *storage.Store, router *proxy.Router, log *slog.Logger) {
	if store == nil {
		return
	}
	apps, err := store.ListApps()
	if err != nil {
		log.Warn("chargement des applications impossible", "err", err)
		return
	}
	router.Reload(apps)
}

// refreshLoop recharge périodiquement (capte les modifications faites en base
// hors de l'API).
func refreshLoop(store *storage.Store, router *proxy.Router, log *slog.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		reloadRouter(store, router, log)
	}
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
