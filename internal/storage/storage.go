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
    upstream_url TEXT NOT NULL,
    mode         TEXT NOT NULL DEFAULT 'block',
    threshold    INT  NOT NULL DEFAULT 4,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
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
