import os
import sqlite3

# Make DB path match backend/app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # backend/
DB_PATH = os.path.join(BASE_DIR, "database.db")

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Drop tables if they exist
c.execute("DROP TABLE IF EXISTS files")
c.execute("DROP TABLE IF EXISTS attempts")

# Recreate files table
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

# Recreate attempts table
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

# Clear attempts (not really needed after DROP, but safe)
c.execute("DELETE FROM attempts")

conn.commit()
conn.close()
print(f"{DB_PATH} initialized")
