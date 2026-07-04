"""
Stockage SQLite : journal des événements + réglages persistants.
Volontairement minimal (une seule dépendance : le module standard sqlite3).
"""

import sqlite3
import json
import time
import threading
from pathlib import Path

DB_PATH = Path(__file__).parent / "waf.db"
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           REAL    NOT NULL,
                client_ip    TEXT    NOT NULL,
                method       TEXT    NOT NULL,
                path         TEXT    NOT NULL,
                verdict      TEXT    NOT NULL,   -- allowed | detected | blocked
                score        INTEGER NOT NULL,
                categories   TEXT    NOT NULL,   -- JSON list
                matched      TEXT    NOT NULL,   -- JSON list de règles
                snippet      TEXT                -- extrait de la requête suspecte
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        conn.commit()


def log_event(ip, method, path, verdict, score, categories, matched, snippet):
    with _lock, _connect() as conn:
        cur = conn.execute(
            """INSERT INTO events
               (ts, client_ip, method, path, verdict, score, categories, matched, snippet)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                time.time(),
                ip,
                method,
                path,
                verdict,
                score,
                json.dumps(categories),
                json.dumps(matched),
                snippet,
            ),
        )
        conn.commit()
        return cur.lastrowid


def get_events(limit=100, since_id=0):
    with _lock, _connect() as conn:
        rows = conn.execute(
            """SELECT * FROM events WHERE id > ? ORDER BY id DESC LIMIT ?""",
            (since_id, limit),
        ).fetchall()
    events = []
    for r in rows:
        events.append(
            {
                "id": r["id"],
                "ts": r["ts"],
                "client_ip": r["client_ip"],
                "method": r["method"],
                "path": r["path"],
                "verdict": r["verdict"],
                "score": r["score"],
                "categories": json.loads(r["categories"]),
                "matched": json.loads(r["matched"]),
                "snippet": r["snippet"],
            }
        )
    return events


def get_stats():
    with _lock, _connect() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE verdict='blocked'"
        ).fetchone()["c"]
        detected = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE verdict='detected'"
        ).fetchone()["c"]
        allowed = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE verdict='allowed'"
        ).fetchone()["c"]
        rows = conn.execute(
            """SELECT categories FROM events
               WHERE verdict IN ('blocked','detected')"""
        ).fetchall()
        top_rows = conn.execute(
            """SELECT client_ip, COUNT(*) c FROM events
               WHERE verdict IN ('blocked','detected')
               GROUP BY client_ip ORDER BY c DESC LIMIT 5"""
        ).fetchall()

    by_category = {}
    for r in rows:
        for cat in json.loads(r["categories"]):
            by_category[cat] = by_category.get(cat, 0) + 1

    return {
        "total": total,
        "blocked": blocked,
        "detected": detected,
        "allowed": allowed,
        "by_category": by_category,
        "top_ips": [{"ip": r["client_ip"], "count": r["c"]} for r in top_rows],
    }


def clear_events():
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM events")
        conn.commit()


def save_setting(key, value):
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
        conn.commit()


def load_setting(key, default=None):
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
    if row is None:
        return default
    return json.loads(row["value"])
