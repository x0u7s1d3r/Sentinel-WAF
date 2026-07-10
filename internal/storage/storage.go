// Package storage assure la persistance des événements du WAF dans PostgreSQL.
//
// Deux principes guident ce paquet :
//  1. Écriture ASYNCHRONE : le proxy ne doit jamais attendre la base. Les
//     événements sont poussés dans un canal tamponné qu'un worker vide en
//     arrière-plan ; si le tampon est plein, on abandonne l'événement plutôt
//     que de ralentir le trafic.
//  2. Dégradation GRACIEUSE : si la base est indisponible, le WAF continue de
//     protéger (les événements sont simplement non persistés). La sécurité ne
//     dépend jamais de la disponibilité de la base.
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/lib/pq"
)

// Event est une requête inspectée, telle qu'on la journalise.
type Event struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	App        string    `json:"app"`
	ClientIP   string    `json:"client_ip"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Verdict    string    `json:"verdict"`
	Score      int       `json:"score"`
	Categories []string  `json:"categories"`
	Findings   any       `json:"findings"`
	LatencyUS  int64     `json:"latency_us"`
}

// Store encapsule la connexion et le worker d'écriture asynchrone.
type Store struct {
	db   *sql.DB
	ch   chan Event
	quit chan struct{}
	// Rétention des événements : le plus strict des deux s'applique.
	retentionDays    int // supprime les événements plus vieux que N jours (0 = illimité)
	retentionMaxRows int // conserve au plus N événements récents (0 = illimité)
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    app        TEXT   NOT NULL DEFAULT 'default',
    client_ip  TEXT   NOT NULL,
    method     TEXT   NOT NULL,
    path       TEXT   NOT NULL,
    verdict    TEXT   NOT NULL,
    score      INT    NOT NULL,
    categories TEXT   NOT NULL,
    findings   JSONB,
    latency_us BIGINT
);
-- pour les bases créées avant l'étiquetage par site
ALTER TABLE events ADD COLUMN IF NOT EXISTS app TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_app_idx ON events (app);

CREATE TABLE IF NOT EXISTS applications (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    domain       TEXT NOT NULL DEFAULT '',
    upstream_url TEXT NOT NULL,
    mode         TEXT NOT NULL DEFAULT 'block',
    threshold    INT  NOT NULL DEFAULT 4,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- pour les bases créées avant l'ajout du routage par domaine
ALTER TABLE applications ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    win_label  TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT '',
    count      INTEGER NOT NULL DEFAULT 0,
    blocked    INTEGER NOT NULL DEFAULT 0,
    detected   INTEGER NOT NULL DEFAULT 0,
    apps       TEXT NOT NULL DEFAULT '',
    categories TEXT NOT NULL DEFAULT '',
    top_ips    TEXT NOT NULL DEFAULT '',
    top_paths  TEXT NOT NULL DEFAULT '',
    analysis   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents (ts DESC);
`

// Open établit la connexion, vérifie qu'elle répond et applique le schéma.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{
		db:               db,
		ch:               make(chan Event, 1024),
		quit:             make(chan struct{}),
		retentionDays:    30,     // défauts sûrs ; surchargés par SetRetention
		retentionMaxRows: 100000, // ceinture + bretelles contre l'explosion de la base
	}
	go s.worker()
	go s.retentionWorker()
	return s, nil
}

// SetRetention configure la politique de rétention (0 = illimité pour chacune).
// Le plus strict des deux critères s'applique lors de la purge.
func (s *Store) SetRetention(days, maxRows int) {
	if s == nil {
		return
	}
	if days >= 0 {
		s.retentionDays = days
	}
	if maxRows >= 0 {
		s.retentionMaxRows = maxRows
	}
}

// retentionWorker purge périodiquement les vieux événements (hors chemin des
// requêtes). En cas d'échec, on journalise et on réessaie au cycle suivant :
// la purge ne doit jamais impacter la protection.
func (s *Store) retentionWorker() {
	// Première purge peu après le démarrage, puis toutes les heures.
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-timer.C:
			s.purge()
			timer.Reset(time.Hour)
		}
	}
}

// purge applique les deux limites de rétention.
func (s *Store) purge() {
	if s == nil || s.db == nil {
		return
	}
	// 1) Par ancienneté.
	if s.retentionDays > 0 {
		q := fmt.Sprintf("DELETE FROM events WHERE ts < now() - interval '%d days'", s.retentionDays)
		if res, err := s.db.Exec(q); err != nil {
			slog.Warn("purge par ancienneté échouée", "err", err)
		} else if n, _ := res.RowsAffected(); n > 0 {
			slog.Info("purge des événements (ancienneté)", "supprimés", n, "jours", s.retentionDays)
		}
	}
	// 2) Par nombre : on ne garde que les N identifiants les plus récents.
	if s.retentionMaxRows > 0 {
		q := `DELETE FROM events WHERE id < (
		         SELECT COALESCE(MIN(id), 0) FROM (
		           SELECT id FROM events ORDER BY id DESC LIMIT $1
		         ) keep
		       )`
		if res, err := s.db.Exec(q, s.retentionMaxRows); err != nil {
			slog.Warn("purge par nombre échouée", "err", err)
		} else if n, _ := res.RowsAffected(); n > 0 {
			slog.Info("purge des événements (nombre max)", "supprimés", n, "max", s.retentionMaxRows)
		}
	}
}

// Log pousse un événement sans bloquer (abandonné si le tampon est saturé).
func (s *Store) Log(ev Event) {
	if s == nil {
		return
	}
	select {
	case s.ch <- ev:
	default: // tampon plein : on préfère perdre un log que ralentir le trafic
	}
}

func (s *Store) worker() {
	for {
		select {
		case ev := <-s.ch:
			s.insert(ev)
		case <-s.quit:
			// vidange finale
			for {
				select {
				case ev := <-s.ch:
					s.insert(ev)
				default:
					return
				}
			}
		}
	}
}

func (s *Store) insert(ev Event) {
	findings, _ := json.Marshal(ev.Findings)
	cats := ""
	for i, c := range ev.Categories {
		if i > 0 {
			cats += ","
		}
		cats += c
	}
	app := ev.App
	if app == "" {
		app = "default"
	}
	_, _ = s.db.Exec(
		`INSERT INTO events (app, client_ip, method, path, verdict, score, categories, findings, latency_us)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		app, ev.ClientIP, ev.Method, ev.Path, ev.Verdict, ev.Score, cats,
		string(findings), ev.LatencyUS,
	)
}

// Recent renvoie les derniers événements (filtré par site si app != "").
func (s *Store) Recent(limit int, app string) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, ts, app, client_ip, method, path, verdict, score, categories, latency_us
	      FROM events WHERE 1=1`
	args := []any{}
	if app != "" {
		q += " AND app = $1"
		args = append(args, app)
	}
	q += " ORDER BY id DESC LIMIT " + itoaLimit(limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var cats string
		if err := rows.Scan(&e.ID, &e.TS, &e.App, &e.ClientIP, &e.Method, &e.Path,
			&e.Verdict, &e.Score, &cats, &e.LatencyUS); err != nil {
			return nil, err
		}
		if cats != "" {
			e.Categories = splitComma(cats)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TimelineByIP reconstitue la session d'une IP : ses requêtes dans l'ordre
// chronologique, plus un résumé (première/dernière vue, totaux, catégories).
func (s *Store) TimelineByIP(ip string, limit int) (map[string]any, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	rows, err := s.db.Query(`
		SELECT id, ts, app, client_ip, method, path, verdict, score, categories, latency_us
		FROM events WHERE client_ip = $1
		ORDER BY id ASC LIMIT `+itoaLimit(limit), ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	byCat := map[string]int{}
	byApp := map[string]int{}
	blocked, detected, allowed, maxScore := 0, 0, 0, 0
	for rows.Next() {
		var e Event
		var cats string
		if err := rows.Scan(&e.ID, &e.TS, &e.App, &e.ClientIP, &e.Method, &e.Path,
			&e.Verdict, &e.Score, &cats, &e.LatencyUS); err != nil {
			return nil, err
		}
		if cats != "" {
			e.Categories = splitComma(cats)
			for _, c := range e.Categories {
				byCat[c]++
			}
		}
		switch e.Verdict {
		case "blocked":
			blocked++
		case "detected":
			detected++
		default:
			allowed++
		}
		if e.Score > maxScore {
			maxScore = e.Score
		}
		if e.App != "" {
			byApp[e.App]++
		}
		events = append(events, e)
	}

	summary := map[string]any{
		"ip": ip, "total": len(events),
		"blocked": blocked, "detected": detected, "allowed": allowed,
		"max_score": maxScore, "categories": byCat, "apps": byApp,
	}
	if len(events) > 0 {
		summary["first_seen"] = events[0].TS
		summary["last_seen"] = events[len(events)-1].TS
	}
	return map[string]any{"summary": summary, "events": events}, rows.Err()
}

func itoaLimit(n int) string {
	digits := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// Stats renvoie des agrégats persistants (filtré par site si app != "").
func (s *Store) Stats(app string) (map[string]any, error) {
	q := `SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE verdict='blocked'),
		  COUNT(*) FILTER (WHERE verdict='detected'),
		  COUNT(*) FILTER (WHERE verdict='allowed')
		FROM events WHERE 1=1`
	args := []any{}
	if app != "" {
		q += " AND app = $1"
		args = append(args, app)
	}
	var total, blocked, detected, allowed int64
	if err := s.db.QueryRow(q, args...).Scan(&total, &blocked, &detected, &allowed); err != nil {
		return nil, err
	}
	return map[string]any{
		"total": total, "blocked": blocked,
		"detected": detected, "allowed": allowed,
	}, nil
}

// Close arrête le worker et ferme la connexion.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.quit)
	time.Sleep(100 * time.Millisecond) // laisse la vidange se terminer
	return s.db.Close()
}

// App est une application protégée par le WAF (une cible en amont).
type App struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Domain      string    `json:"domain"`       // hôte à router, ex. "app.exemple.tg"
	UpstreamURL string    `json:"upstream_url"` // backend réel, ex. "http://127.0.0.1:9001"
	Mode        string    `json:"mode"`         // "block" | "detect" (propre à l'appli)
	Threshold   int       `json:"threshold"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListApps renvoie toutes les applications enregistrées.
func (s *Store) ListApps() ([]App, error) {
	rows, err := s.db.Query(
		`SELECT id, name, domain, upstream_url, mode, threshold, created_at
		 FROM applications ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Name, &a.Domain, &a.UpstreamURL,
			&a.Mode, &a.Threshold, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddApp enregistre une nouvelle application et renvoie sa version complète.
func (s *Store) AddApp(a App) (App, error) {
	if a.Mode == "" {
		a.Mode = "block"
	}
	if a.Threshold <= 0 {
		a.Threshold = 4
	}
	err := s.db.QueryRow(
		`INSERT INTO applications (name, domain, upstream_url, mode, threshold)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		a.Name, a.Domain, a.UpstreamURL, a.Mode, a.Threshold,
	).Scan(&a.ID, &a.CreatedAt)
	return a, err
}

// DeleteApp supprime une application par son identifiant.
func (s *Store) DeleteApp(id int64) error {
	_, err := s.db.Exec(`DELETE FROM applications WHERE id = $1`, id)
	return err
}

// UpdateApp modifie une application. Les champs nom/domaine/backend ne sont
// mis à jour que s'ils sont non vides (permet une bascule mode/seuil seule).
func (s *Store) UpdateApp(id int64, name, domain, upstream, mode string, threshold int) error {
	if mode != "block" && mode != "detect" {
		mode = "block"
	}
	if threshold < 1 {
		threshold = 4
	}
	_, err := s.db.Exec(
		`UPDATE applications SET
		   name = COALESCE(NULLIF($2,''), name),
		   domain = COALESCE(NULLIF($3,''), domain),
		   upstream_url = COALESCE(NULLIF($4,''), upstream_url),
		   mode = $5,
		   threshold = $6
		 WHERE id = $1`,
		id, name, domain, upstream, mode, threshold)
	return err
}

// Incident représente un épisode d'attaques ayant déclenché une alerte.
type Incident struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Window     string    `json:"window"`
	Severity   string    `json:"severity"`
	Count      int       `json:"count"`
	Blocked    int       `json:"blocked"`
	Detected   int       `json:"detected"`
	Apps       string    `json:"apps"`
	Categories string    `json:"categories"`
	TopIPs     string    `json:"top_ips"`
	TopPaths   string    `json:"top_paths"`
	Analysis   string    `json:"analysis"`
}

// SaveIncident enregistre un incident dans l'historique.
func (s *Store) SaveIncident(in Incident) error {
	if s == nil {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO incidents (win_label, severity, count, blocked, detected, apps, categories, top_ips, top_paths, analysis)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		in.Window, in.Severity, in.Count, in.Blocked, in.Detected,
		in.Apps, in.Categories, in.TopIPs, in.TopPaths, in.Analysis)
	return err
}

// ListIncidents renvoie les incidents les plus récents (limite bornée).
func (s *Store) ListIncidents(limit int) ([]Incident, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT id, ts, win_label, severity, count, blocked, detected, apps, categories, top_ips, top_paths, analysis
		FROM incidents ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		if err := rows.Scan(&in.ID, &in.TS, &in.Window, &in.Severity, &in.Count,
			&in.Blocked, &in.Detected, &in.Apps, &in.Categories, &in.TopIPs,
			&in.TopPaths, &in.Analysis); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, nil
}

// SaveSetting persiste une valeur de configuration (sérialisée en JSON).
func (s *Store) SaveSetting(key string, v any) error {
	if s == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = $2`, key, string(b))
	return err
}

// LoadSetting lit une valeur de configuration dans dest. found=false si absente.
func (s *Store) LoadSetting(key string, dest any) (bool, error) {
	if s == nil {
		return false, nil
	}
	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = $1`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(val), dest)
}

// Analytics renvoie toutes les agrégations nécessaires au tableau de bord SOC,
// en un seul appel : séries temporelles (trafic par minute), répartition par
// catégorie, top IP attaquantes, top URLs ciblées, et bilan des verdicts.
// rangeParams traduit une plage ("1h","24h","72h","7d","30d","all") en fenêtre
// de temps et pas d'agrégation (en secondes), pour garder un nombre de points
// lisible quelle que soit la durée.
func rangeParams(rng string) (windowSec, bucketSec int64) {
	switch rng {
	case "24h":
		return 86400, 900 // 24 h, pas de 15 min  -> 96 points
	case "72h":
		return 259200, 3600 // 72 h, pas de 1 h    -> 72 points
	case "7d":
		return 604800, 10800 // 7 j, pas de 3 h    -> 56 points
	case "30d":
		return 2592000, 86400 // 30 j, pas de 1 j  -> 30 points
	case "all":
		return 0, 86400 // tout l'historique, pas de 1 j
	default: // "1h"
		return 3600, 60 // 1 h, pas de 1 min       -> 60 points
	}
}

func (s *Store) Analytics(app, rng string) (map[string]any, error) {
	out := map[string]any{}
	// Filtrage par site : "" ou " AND app=$1".
	af := ""
	args := []any{}
	if app != "" {
		af = " AND app = $1"
		args = append(args, app)
	}
	windowSec, bucketSec := rangeParams(rng)
	// Clause de fenêtre temporelle (vide pour "all").
	tf := ""
	if windowSec > 0 {
		tf = fmt.Sprintf(" AND ts > now() - interval '%d seconds'", windowSec)
	}
	out["range"] = rng

	// 1) Série temporelle : trafic agrégé par tranche (bucket) adaptée à la plage.
	//    On génère une série CONTINUE sur toute la fenêtre (tranches vides à 0)
	//    pour un graphe correct, sauf pour "all" (pas de borne de départ fixe).
	if windowSec > 0 {
		tsQuery := fmt.Sprintf(`
			WITH bounds AS (
			  SELECT floor(extract(epoch from now())/%d)*%d AS b_end,
			         floor(extract(epoch from now() - interval '%d seconds')/%d)*%d AS b_start
			),
			buckets AS (
			  SELECT generate_series(b_start, b_end, %d) AS ep FROM bounds
			),
			agg AS (
			  SELECT floor(extract(epoch from ts)/%d)*%d AS ep,
			         COUNT(*) t,
			         COUNT(*) FILTER (WHERE verdict='blocked') b,
			         COUNT(*) FILTER (WHERE verdict='detected') d,
			         COUNT(*) FILTER (WHERE verdict='allowed') a
			  FROM events WHERE 1=1%s%s GROUP BY 1
			)
			SELECT to_char(to_timestamp(bk.ep) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:00"Z"'),
			       COALESCE(ag.t,0), COALESCE(ag.b,0), COALESCE(ag.d,0), COALESCE(ag.a,0)
			FROM buckets bk LEFT JOIN agg ag ON ag.ep = bk.ep
			ORDER BY bk.ep`,
			bucketSec, bucketSec, windowSec, bucketSec, bucketSec, bucketSec,
			bucketSec, bucketSec, af, tf)
		if rows, err := s.db.Query(tsQuery, args...); err == nil {
			var series []map[string]any
			for rows.Next() {
				var b string
				var total, blocked, detected, allowed int64
				if rows.Scan(&b, &total, &blocked, &detected, &allowed) == nil {
					series = append(series, map[string]any{
						"t": b, "total": total, "blocked": blocked,
						"detected": detected, "allowed": allowed,
					})
				}
			}
			rows.Close()
			out["timeseries"] = series
		}
	} else {
		// "all" : série éparse (regroupement simple, sans borne de départ).
		tsQuery := fmt.Sprintf(`
			SELECT to_char(to_timestamp(floor(extract(epoch from ts)/%d)*%d) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:00"Z"'),
			       COUNT(*),
			       COUNT(*) FILTER (WHERE verdict='blocked'),
			       COUNT(*) FILTER (WHERE verdict='detected'),
			       COUNT(*) FILTER (WHERE verdict='allowed')
			FROM events WHERE 1=1%s%s
			GROUP BY 1 ORDER BY 1`, bucketSec, bucketSec, af, tf)
		if rows, err := s.db.Query(tsQuery, args...); err == nil {
			var series []map[string]any
			for rows.Next() {
				var b string
				var total, blocked, detected, allowed int64
				if rows.Scan(&b, &total, &blocked, &detected, &allowed) == nil {
					series = append(series, map[string]any{
						"t": b, "total": total, "blocked": blocked,
						"detected": detected, "allowed": allowed,
					})
				}
			}
			rows.Close()
			out["timeseries"] = series
		}
	}

	// 2) Répartition par catégorie (sur la période).
	if rows, err := s.db.Query(`
		SELECT cat, COUNT(*) c FROM (
		  SELECT unnest(string_to_array(categories, ',')) AS cat
		  FROM events WHERE categories <> ''`+af+tf+`
		) s WHERE cat <> '' GROUP BY cat ORDER BY c DESC`, args...); err == nil {
		var cats []map[string]any
		for rows.Next() {
			var cat string
			var c int64
			if rows.Scan(&cat, &c) == nil {
				cats = append(cats, map[string]any{"category": cat, "count": c})
			}
		}
		rows.Close()
		out["by_category"] = cats
	}

	// 3) Top IP par volume d'attaques (sur la période).
	if rows, err := s.db.Query(`
		SELECT client_ip, COUNT(*),
		       COUNT(*) FILTER (WHERE verdict IN ('blocked','detected'))
		FROM events WHERE 1=1`+af+tf+`
		GROUP BY client_ip ORDER BY 3 DESC, 2 DESC LIMIT 8`, args...); err == nil {
		var ips []map[string]any
		for rows.Next() {
			var ip string
			var total, attacks int64
			if rows.Scan(&ip, &total, &attacks) == nil {
				ips = append(ips, map[string]any{"ip": ip, "total": total, "attacks": attacks})
			}
		}
		rows.Close()
		out["top_ips"] = ips
	}

	// 4) Top URLs ciblées par des attaques (sur la période).
	if rows, err := s.db.Query(`
		SELECT path, COUNT(*) c FROM events
		WHERE verdict <> 'allowed'`+af+tf+`
		GROUP BY path ORDER BY c DESC LIMIT 8`, args...); err == nil {
		var paths []map[string]any
		for rows.Next() {
			var p string
			var c int64
			if rows.Scan(&p, &c) == nil {
				paths = append(paths, map[string]any{"path": p, "count": c})
			}
		}
		rows.Close()
		out["top_paths"] = paths
	}

	// 5) Bilan des verdicts (réutilise Stats, filtré par site).
	if st, err := s.Stats(app); err == nil {
		out["verdicts"] = st
	}

	// 6) Dernière analyse IA disponible (le cas échéant).
	var ai map[string]any
	if ok, _ := s.LoadSetting("latest_analysis", &ai); ok {
		out["ai_analysis"] = ai
	}

	// 7) Score des attaques : moyenne et maximum sur la période, plus un
	//    « niveau de menace » synthétique (0-100) combinant intensité et volume.
	var avgScore, maxScore float64
	var attackCount int64
	_ = s.db.QueryRow(`
		SELECT COALESCE(AVG(score),0), COALESCE(MAX(score),0), COUNT(*)
		FROM events WHERE verdict IN ('blocked','detected')`+af+tf, args...).
		Scan(&avgScore, &maxScore, &attackCount)

	// Niveau de menace : le score moyen donne l'intensité (rapporté sur 100 en
	// supposant un score « critique » autour de 10), pondéré à la hausse quand le
	// volume d'attaques est important. Borné à 100.
	threat := avgScore * 10
	if attackCount > 20 {
		threat += 15
	} else if attackCount > 5 {
		threat += 8
	}
	if threat > 100 {
		threat = 100
	}
	level := "faible"
	switch {
	case threat >= 70:
		level = "critique"
	case threat >= 40:
		level = "élevé"
	case threat >= 15:
		level = "modéré"
	}
	out["threat_score"] = map[string]any{
		"avg":     round1(avgScore),
		"max":     int(maxScore),
		"attacks": attackCount,
		"level":   level,
		"gauge":   int(threat),
	}

	return out, nil
}

// round1 arrondit à une décimale.
func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out
}
