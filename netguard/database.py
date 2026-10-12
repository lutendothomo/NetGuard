import sqlite3
from contextlib import contextmanager
from netguard.config import settings

def get_connection():
    conn = sqlite3.connect(settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@contextmanager
def connection():
    conn = get_connection()
    try:
        with conn:
            yield conn
    finally:
        conn.close()

def init_db():
    with connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'auditor'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operator TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp REAL NOT NULL,
                findings_summary TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                mac TEXT,
                vendor TEXT,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL REFERENCES hosts(id),
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                state TEXT NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,
                banner TEXT,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                UNIQUE(host_id, port, protocol)
            )
        """)
