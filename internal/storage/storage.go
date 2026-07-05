// Package storage assure la persistance des événements du WAF dans PostgreSQL.
//
// Deux principes guident ce paquet :
//   1. Écriture ASYNCHRONE : le proxy ne doit jamais attendre la base. Les
//      événements sont poussés dans un canal tamponné qu'un worker vide en
//      arrière-plan ; si le tampon est plein, on abandonne l'événement plutôt
//      que de ralentir le trafic.
//   2. Dégradation GRACIEUSE : si la base est indisponible, le WAF continue de
//      protéger (les événements sont simplement non persistés). La sécurité ne
//      dépend jamais de la disponibilité de la base.
package storage

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/lib/pq"
)

// Event est une requête inspectée, telle qu'on la journalise.
type Event struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
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
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_ip  TEXT   NOT NULL,
    method     TEXT   NOT NULL,
    path       TEXT   NOT NULL,
    verdict    TEXT   NOT NULL,
    score      INT    NOT NULL,
    categories TEXT   NOT NULL,
    findings   JSONB,
    latency_us BIGINT
);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);

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
	s := &Store{db: db, ch: make(chan Event, 1024), quit: make(chan struct{})}
	go s.worker()
	return s, nil
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
	_, _ = s.db.Exec(
		`INSERT INTO events (client_ip, method, path, verdict, score, categories, findings, latency_us)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		ev.ClientIP, ev.Method, ev.Path, ev.Verdict, ev.Score, cats,
		string(findings), ev.LatencyUS,
	)
}

// Recent renvoie les derniers événements (pour le dashboard / l'API).
func (s *Store) Recent(limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, client_ip, method, path, verdict, score, categories, latency_us
		 FROM events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var cats string
		if err := rows.Scan(&e.ID, &e.TS, &e.ClientIP, &e.Method, &e.Path,
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

// Stats renvoie des agrégats persistants (survivent au redémarrage).
func (s *Store) Stats() (map[string]any, error) {
	row := s.db.QueryRow(`
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE verdict='blocked'),
		  COUNT(*) FILTER (WHERE verdict='detected'),
		  COUNT(*) FILTER (WHERE verdict='allowed')
		FROM events`)
	var total, blocked, detected, allowed int64
	if err := row.Scan(&total, &blocked, &detected, &allowed); err != nil {
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
func (s *Store) Analytics() (map[string]any, error) {
	out := map[string]any{}

	// 1) Série temporelle : trafic par minute sur la dernière heure.
	if rows, err := s.db.Query(`
		SELECT to_char(date_trunc('minute', ts) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:00"Z"'),
		       COUNT(*),
		       COUNT(*) FILTER (WHERE verdict='blocked'),
		       COUNT(*) FILTER (WHERE verdict='detected'),
		       COUNT(*) FILTER (WHERE verdict='allowed')
		FROM events
		WHERE ts > now() - interval '60 minutes'
		GROUP BY 1 ORDER BY 1`); err == nil {
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

	// 2) Répartition par catégorie (la colonne stocke une liste séparée par ',').
	if rows, err := s.db.Query(`
		SELECT cat, COUNT(*) c FROM (
		  SELECT unnest(string_to_array(categories, ',')) AS cat
		  FROM events WHERE categories <> ''
		) s WHERE cat <> '' GROUP BY cat ORDER BY c DESC`); err == nil {
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

	// 3) Top IP par volume d'attaques.
	if rows, err := s.db.Query(`
		SELECT client_ip, COUNT(*),
		       COUNT(*) FILTER (WHERE verdict IN ('blocked','detected'))
		FROM events GROUP BY client_ip
		ORDER BY 3 DESC, 2 DESC LIMIT 8`); err == nil {
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

	// 4) Top URLs ciblées par des attaques.
	if rows, err := s.db.Query(`
		SELECT path, COUNT(*) c FROM events
		WHERE verdict <> 'allowed' GROUP BY path ORDER BY c DESC LIMIT 8`); err == nil {
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

	// 5) Bilan des verdicts (réutilise Stats).
	if st, err := s.Stats(); err == nil {
		out["verdicts"] = st
	}

	return out, nil
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
