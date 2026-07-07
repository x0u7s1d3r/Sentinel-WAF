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
	"strings"
	"syscall"
	"time"

	"sentinel-waf/internal/auth"
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
		detector.SensitivePath{},
		detector.NewBruteForce(),
	)

	// Alertes Slack (facultatif) : actives seulement si un webhook est fourni
	// par l'environnement. Intervalle d'agrégation réglable (défaut 15 s).
	alertInterval := 15 * time.Second
	if v := os.Getenv("SENTINEL_ALERT_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			alertInterval = time.Duration(n) * time.Second
		}
	}
	// Configuration modifiable à chaud (mode, seuil, catégories, blocklist,
	// webhook Slack), initialisée depuis le fichier puis l'état persisté en base.
	settings := proxy.NewSettings(cfg.Mode, cfg.Threshold, store)

	// Notificateur Slack : le webhook persisté (défini via le dashboard) a la
	// priorité ; sinon on retombe sur la variable d'environnement.
	slackInit := settings.SlackWebhook()
	if slackInit == "" {
		slackInit = cfg.SlackWebhook
	}
	discordInit := settings.DiscordWebhook()
	if discordInit == "" {
		discordInit = cfg.DiscordWebhook
	}
	notif := notifier.New(slackInit, discordInit, alertInterval, log)
	defer notif.Close()
	if notif.Configured(notifier.KindSlack) || notif.Configured(notifier.KindDiscord) {
		log.Info("alertes activées", "slack", notif.Configured(notifier.KindSlack),
			"discord", notif.Configured(notifier.KindDiscord), "intervalle", alertInterval)
	} else {
		log.Info("alertes en attente d'un webhook (configurable depuis le dashboard)")
	}

	// Routeur multi-application : chargé depuis la base, rechargé à chaud.
	router := proxy.NewRouter()
	reloadRouter(store, router, log)
	if store != nil {
		go refreshLoop(store, router, log) // capte les changements externes
	}

	gw, err := proxy.New(cfg, chain, log, store, router, notif, settings)
	if err != nil {
		log.Error("initialisation passerelle", "err", err)
		os.Exit(1)
	}

	// --- Authentification admin (secret de signature + hachage du mot de passe) ---
	var authSecret []byte
	var adminHash string
	if store != nil {
		var sec string
		if ok, _ := store.LoadSetting("auth_secret", &sec); ok && sec != "" {
			authSecret = auth.DecodeSecret(sec)
		} else {
			sec = auth.NewSecret()
			_ = store.SaveSetting("auth_secret", sec)
			authSecret = auth.DecodeSecret(sec)
		}
		_, _ = store.LoadSetting("admin_hash", &adminHash)
	} else {
		authSecret = auth.DecodeSecret(auth.NewSecret()) // éphémère sans base
	}
	admin := auth.NewAdmin(adminHash, authSecret, func(h string) {
		if store != nil {
			_ = store.SaveSetting("admin_hash", h)
		}
	})
	// Un mot de passe fourni par l'environnement (re)définit le compte admin
	// (utile pour réinitialiser un mot de passe oublié).
	if cfg.AdminPassword != "" {
		admin.SetPassword(cfg.AdminPassword)
	}
	if admin.Enabled() {
		log.Info("authentification admin active")
	} else {
		log.Warn("aucun compte admin — création requise au premier accès au dashboard")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_sentinel/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"status": "ok", "mode": settings.Mode(),
			"persistence": store != nil, "apps": router.Count(),
			"auth_required":  admin.Enabled(),
			"account_exists": admin.Enabled(),
		})
	})

	// Création du compte admin au premier lancement (ouvert tant qu'aucun compte
	// n'existe ; refusé ensuite). Délivre un jeton pour connecter immédiatement.
	mux.HandleFunc("/_sentinel/setup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
			return
		}
		if admin.Enabled() {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]any{"ok": false, "error": "un compte administrateur existe déjà"})
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Password) < 6 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"ok": false, "error": "mot de passe trop court (6 caractères minimum)"})
			return
		}
		admin.SetPassword(body.Password)
		log.Info("compte administrateur créé")
		writeJSON(w, map[string]any{"ok": true, "token": admin.Token(12 * time.Hour)})
	})

	// Connexion : vérifie le mot de passe et délivre un jeton (endpoint ouvert).
	mux.HandleFunc("/_sentinel/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !admin.Enabled() {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]any{"ok": false, "error": "aucun compte : créez-le d'abord"})
			return
		}
		if !admin.Verify(body.Password) {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"ok": false, "error": "identifiants invalides"})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "token": admin.Token(12 * time.Hour)})
	})

	// Changement de mot de passe (protégé par le middleware) : exige l'ancien.
	mux.HandleFunc("/_sentinel/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Old string `json:"old"`
			New string `json:"new"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !admin.Verify(body.Old) {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"ok": false, "error": "mot de passe actuel incorrect"})
			return
		}
		if len(body.New) < 6 {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"ok": false, "error": "nouveau mot de passe trop court (6 caractères minimum)"})
			return
		}
		admin.SetPassword(body.New)
		log.Info("mot de passe administrateur modifié")
		writeJSON(w, map[string]any{"ok": true})
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
		a, err := store.Analytics(r.URL.Query().Get("app"), r.URL.Query().Get("range"))
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
				Mode              *string   `json:"mode"`
				Threshold         *int      `json:"threshold"`
				EnabledCategories *[]string `json:"enabled_categories"`
				SlackWebhook      *string   `json:"slack_webhook"`
				DiscordWebhook    *string   `json:"discord_webhook"`
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
			if body.SlackWebhook != nil {
				settings.SetSlackWebhook(*body.SlackWebhook)
				notif.SetWebhook(notifier.KindSlack, *body.SlackWebhook) // à chaud
			}
			if body.DiscordWebhook != nil {
				settings.SetDiscordWebhook(*body.DiscordWebhook)
				notif.SetWebhook(notifier.KindDiscord, *body.DiscordWebhook) // à chaud
			}
			writeJSON(w, settings.Snapshot())
		default:
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
		}
	})

	// --- Test d'alerte (envoi immédiat) : /_sentinel/{slack,discord}/test ---
	testHandler := func(kind string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
				return
			}
			if err := notif.Test(kind); err != nil {
				writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			writeJSON(w, map[string]any{"ok": true})
		}
	}
	mux.HandleFunc("/_sentinel/slack/test", testHandler(notifier.KindSlack))
	mux.HandleFunc("/_sentinel/discord/test", testHandler(notifier.KindDiscord))

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

	// Middleware d'authentification : protège toute l'API de contrôle
	// (/_sentinel/*) sauf /login et /health. Le trafic applicatif ("/") passe
	// par le proxy WAF et n'est jamais concerné. Sans jeton valide -> 401.
	// Middleware d'authentification : protège toute l'API de contrôle
	// (/_sentinel/*) sauf /health, /login et /setup. Le trafic applicatif ("/")
	// passe par le proxy WAF et n'est jamais concerné. Sans jeton valide -> 401.
	openPaths := map[string]bool{
		"/_sentinel/health": true,
		"/_sentinel/login":  true,
		"/_sentinel/setup":  true,
	}
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/_sentinel/") && !openPaths[p] {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !admin.Valid(tok) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "authentification requise"})
				return
			}
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{Addr: cfg.Listen, Handler: guarded}
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
