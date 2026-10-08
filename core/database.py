# core/database.py
"""Single source of truth for the SQLite schema (used by recon.py and scripts/)."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, db_path="bug_bounty.db"):
        self.db_path = Path(__file__).resolve().parent.parent / db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                status TEXT,
                notes TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                hostname TEXT,
                ip TEXT,
                status_code INTEGER,
                title TEXT,
                tech TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)
        # Migrate DBs created by the old recon.py (columns: target, scan_date, status)
        cols = {r[1] for r in cur.execute("PRAGMA table_info(scans)")}
        for col in ("started_at", "finished_at", "notes"):
            if col not in cols:
                cur.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
        if "scan_date" in cols:
            cur.execute("UPDATE scans SET started_at = scan_date WHERE started_at IS NULL")
        self.conn.commit()

    def start_scan(self, target):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO scans (target, started_at, status) VALUES (?, ?, ?)",
                    (target, _now(), "running"))
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id, status="completed", notes=""):
        self.conn.execute("UPDATE scans SET finished_at=?, status=?, notes=? WHERE id=?",
                          (_now(), status, notes, scan_id))
        self.conn.commit()

    def add_hosts_bulk(self, scan_id, hosts):
        self.conn.executemany(
            "INSERT INTO hosts (scan_id, hostname, ip, status_code, title, tech) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(scan_id, h.get("hostname"), h.get("ip"), h.get("status_code"),
              h.get("title"), h.get("tech")) for h in hosts])
        self.conn.commit()

    def close(self):
        self.conn.close()


_db_instance = None


def get_db():
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
