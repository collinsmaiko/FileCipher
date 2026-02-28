import os
import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, abort
)
from werkzeug.utils import secure_filename

DB_PATH = "database.db"

# ------------ SECURITY CONFIG ------------
app = Flask(__name__)

# Strong secret key for sessions (for production, set via env var)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Max upload size (100 MB)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# Restrict allowed extensions
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif",
    "zip", "rar", "7z", "mp4", "mp3", "mov",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "apk", "exe"
}

# Character set for codes: A‑Z + 0‑9
CODE_ALPHABET = string.ascii_uppercase + string.digits


# ---------- DB helper ----------
def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- file validation ----------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


# ---------- code normalization (user-provided) ----------
def normalize_code(raw: str) -> str:
    # keep only A–Z and 0–9, force uppercase
    return "".join(ch for ch in raw.upper() if ch in CODE_ALPHABET)


# ---------- attempt tracking: 10 tries, 1-hour lock ----------
def get_attempt_record(ip: str):
    conn = get_db()
    cur = conn.cursor()

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

    cur.execute(
        "SELECT count, last_attempt, locked_until FROM attempts WHERE ip = ?",
        (ip,),
    )
    row = cur.fetchone()
    conn.close()
    return row


def is_locked(ip: str) -> bool:
    row = get_attempt_record(ip)
    if not row:
        return False
    _, _, locked_until = row
    if not locked_until:
        return False
    try:
        return datetime.fromisoformat(locked_until) > datetime.utcnow()
    except ValueError:
        return False


def update_attempts(ip: str, success: bool):
    now = datetime.utcnow()
    conn = get_db()
    cur = conn.cursor()

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

    cur.execute(
        "SELECT count, last_attempt, locked_until FROM attempts WHERE ip = ?",
        (ip,),
    )
    row = cur.fetchone()

    if success:
        if row:
            cur.execute("DELETE FROM attempts WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return

    if row is None:
        cur.execute(
            "INSERT INTO attempts (ip, count, last_attempt, locked_until) VALUES (?, ?, ?, ?)",
            (ip, 1, now.isoformat(), None),
        )
    else:
        count, last_attempt, locked_until = row

        # If still locked, do nothing
        if locked_until:
            try:
                if datetime.fromisoformat(locked_until) > now:
                    conn.close()
                    return
            except ValueError:
                pass

        if last_attempt:
            try:
                last_dt = datetime.fromisoformat(last_attempt)
                if now - last_dt > timedelta(hours=1):
                    new_count = 1
                else:
                    new_count = count + 1
            except ValueError:
                new_count = 1
        else:
            new_count = 1

        new_locked = None
        if new_count >= 10:
            new_locked = (now + timedelta(hours=1)).isoformat()

        cur.execute(
            """
            UPDATE attempts
            SET count = ?, last_attempt = ?, locked_until = ?
            WHERE ip = ?
            """,
            (new_count, now.isoformat(), new_locked, ip),
        )

    conn.commit()
    conn.close()


# ---------- routes ----------
@app.after_request
def set_security_headers(response):
    # Basic hardening headers
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part in request.")
        return redirect(url_for("index"))

    f = request.files["file"]
    if f.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    filename = secure_filename(f.filename)
    if not allowed_file(filename):
        flash("File type not allowed.")
        return redirect(url_for("index"))

    # ----- user-provided code -----
    raw_code = (request.form.get("code") or "").strip()
    user_code = normalize_code(raw_code)

    if not user_code:
        flash("Please enter a code using only letters A–Z and numbers 0–9.")
        return redirect(url_for("index"))

    if len(user_code) < 4:
        flash("Code is too short. Use at least 4 characters.")
        return redirect(url_for("index"))

    if len(user_code) > 32:
        flash("Code is too long. Use at most 32 characters.")
        return redirect(url_for("index"))

    file_bytes = f.read()
    if not file_bytes:
        flash("Uploaded file is empty.")
        return redirect(url_for("index"))

    # Limit size again as defense in depth
    if len(file_bytes) > app.config["MAX_CONTENT_LENGTH"]:
        flash("File too large.")
        return redirect(url_for("index"))

    mimetype = f.mimetype or "application/octet-stream"

    conn = get_db()
    cur = conn.cursor()

    # Ensure files table exists
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            mimetype TEXT NOT NULL,
            data BLOB NOT NULL,
            uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Check code uniqueness
    cur.execute("SELECT 1 FROM files WHERE code = ?", (user_code,))
    if cur.fetchone():
        conn.close()
        flash("That code is already in use. Please choose a different code.")
        return redirect(url_for("index"))

    # Store using user-chosen code
    cur.execute(
        """
        INSERT INTO files (code, filename, mimetype, data)
        VALUES (?, ?, ?, ?)
        """,
        (user_code, filename, mimetype, file_bytes),
    )
    conn.commit()
    conn.close()

    return render_template("upload_success.html", code=user_code, filename=filename)


@app.route("/receive", methods=["GET", "POST"])
def receive():
    ip = request.remote_addr or "unknown"

    if is_locked(ip):
        flash("Too many wrong codes from your IP. Try again in 1 hour.")
        return render_template("receive.html", file=None)

    file_record = None

    if request.method == "POST":
        # get code user typed in
        code = (request.form.get("code") or "").strip().upper()
        if not code:
            flash("Please enter a code.")
            return render_template("receive.html", file=None)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, code, filename FROM files WHERE code = ?",
            (code,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            update_attempts(ip, success=False)
            flash("Invalid code. You have 10 attempts per hour.")
            return render_template("receive.html", file=None)

        update_attempts(ip, success=True)
        file_record = {
            "id": row["id"],
            "code": row["code"],
            "filename": row["filename"],
        }

    # GET: show empty form; POST success: show download button
    return render_template("receive.html", file=file_record)


@app.route("/download/<int:file_id>/<code>")
def download(file_id, code):
    ip = request.remote_addr or "unknown"

    if is_locked(ip):
        return "Access locked for this IP. Try again in 1 hour.", 429

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT code, filename, mimetype, data FROM files WHERE id = ?",
        (file_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        abort(404, description="File not found.")

    if row["code"] != code.upper():
        update_attempts(ip, success=False)
        abort(403, description="Invalid code for this file.")

    update_attempts(ip, success=True)

    return send_file(
        BytesIO(row["data"]),
        as_attachment=True,
        download_name=row["filename"],
        mimetype=row["mimetype"],
        max_age=0,
        conditional=True,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
