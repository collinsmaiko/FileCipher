import sqlite3

from flask import current_app


def get_db():
    conn = sqlite3.connect(current_app.config["DB_PATH"], detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                mimetype TEXT NOT NULL,
                data BLOB NOT NULL,
                storage_path TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Backfill schema for older databases created before storage_path existed.
        cur.execute("PRAGMA table_info(files)")
        columns = {row["name"] for row in cur.fetchall()}
        if "storage_path" not in columns:
            cur.execute("ALTER TABLE files ADD COLUMN storage_path TEXT")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                ip TEXT,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                ip TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT,
                locked_until TEXT
            )
            """
        )

        conn.commit()
