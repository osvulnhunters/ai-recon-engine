# core/database.py
import sqlite3
from pathlib import Path
from datetime import datetime

class Database:
    def __init__(self, db_path="bug_bounty.db"):
        self.db_path = Path(__file__).parent.parent / db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                status TEXT,
                notes TEXT
            )
        """)
        cursor.execute("""
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
        self.conn.commit()

    def start_scan(self, target):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO scans (target, started_at, status) VALUES (?, ?, ?)",
            (target, datetime.utcnow().isoformat(), "running")
        )
        self.conn.commit()
        return cursor.lastrowid

    def finish_scan(self, scan_id, status="done", notes=""):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE scans SET finished_at=?, status=?, notes=? WHERE id=?",
            (datetime.utcnow().isoformat(), status, notes, scan_id)
        )
        self.conn.commit()

    def add_hosts_bulk(self, scan_id, hosts):
        cursor = self.conn.cursor()
        for host in hosts:
            cursor.execute("""
                INSERT INTO hosts (scan_id, hostname, ip, status_code, title, tech)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id, host.get("hostname"), host.get("ip"),
                host.get("status_code"), host.get("title"), host.get("tech")
            ))
        self.conn.commit()

_db_instance = None
def get_db():
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
