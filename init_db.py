import sqlite3

DB_PATH = "database.db"

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute("DROP TABLE IF EXISTS files")
c.execute("DROP TABLE IF EXISTS attempts")

c.execute(
    """
    CREATE TABLE files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        filename TEXT NOT NULL,
        mimetype TEXT NOT NULL,
        data BLOB NOT NULL,
        uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """
)

c.execute(
    """
    CREATE TABLE attempts (
        ip TEXT PRIMARY KEY,
        count INTEGER NOT NULL DEFAULT 0,
        last_attempt TEXT,
        locked_until TEXT
    )
    """
)

c.execute("DELETE FROM attempts")

conn.commit()
conn.close()
print("database.db initialized")
