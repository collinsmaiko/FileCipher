import os
import sqlite3
import secrets
import string
import uuid
import glob
import threading
import time
from pathlib import Path
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from io import BytesIO
from flask_cors import CORS
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, abort, jsonify
)

# ------------ PATHS / CONFIG ------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # backend/
DB_PATH = os.path.join(BASE_DIR, "database.db")
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")

FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")
FRONTEND_TEMPLATES = os.path.join(FRONTEND_DIR, "templates")
FRONTEND_STATIC = os.path.join(FRONTEND_DIR, "static")

os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# Tell Flask to use templates from frontend/templates and static from frontend/static
app = Flask(
    __name__,
    template_folder=FRONTEND_TEMPLATES,
    static_folder=FRONTEND_STATIC,
)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "MySecretPassword123"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB

# Enable CORS if your frontend runs on a different origin (optional)
CORS(app, resources={r"/*": {"origins": "*"}})

ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif",
    "zip", "rar", "7z", "mp4", "mp3", "mov",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "apk", "exe"
}

CODE_ALPHABET = string.ascii_uppercase + string.digits

# Global tracking for TikTok downloads
download_progress = {}
download_files = {}


# ---------- SINGLE DB HELPER ----------
def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- CREATE ALL TABLES ONCE ----------
def create_tables():
    with get_db() as conn:
        cur = conn.cursor()

        # Files table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                mimetype TEXT NOT NULL,
                data BLOB NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Downloads log
        cur.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                ip TEXT,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Attempts tracking
        cur.execute("""
            CREATE TABLE IF NOT EXISTS attempts (
                ip TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                last_attempt TEXT,
                locked_until TEXT
            )
        """)

        # TikTok downloads log
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tiktok_downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_url TEXT,
                ip TEXT,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


create_tables()


# ---------- HELPERS ----------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def normalize_code(raw: str) -> str:
    return "".join(ch for ch in raw.upper() if ch in CODE_ALPHABET)


def get_attempt_record(ip: str):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT count, last_attempt, locked_until FROM attempts WHERE ip = ?", (ip,))
        row = cur.fetchone()
        return row if row else (0, None, None)


def is_locked(ip: str) -> bool:
    row = get_attempt_record(ip)
    if not row[2]:
        return False
    try:
        return datetime.fromisoformat(row[2]) > datetime.utcnow()
    except ValueError:
        return False


def update_attempts(ip: str, success: bool):
    now = datetime.utcnow()
    with get_db() as conn:
        cur = conn.cursor()
        row = get_attempt_record(ip)

        if success:
            cur.execute("DELETE FROM attempts WHERE ip = ?", (ip,))
            conn.commit()
            return

        count, last_attempt, locked_until = row

        if locked_until and datetime.fromisoformat(locked_until) > now:
            return

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

        new_locked = (now + timedelta(hours=1)).isoformat() if new_count >= 10 else None

        cur.execute(
            "INSERT OR REPLACE INTO attempts (ip, count, last_attempt, locked_until) VALUES (?, ?, ?, ?)",
            (ip, new_count, now.isoformat(), new_locked)
        )
        conn.commit()


# ---------- SECURITY HEADERS ----------
@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# ---------- ROUTES ----------
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

    raw_code = (request.form.get("code") or "").strip()
    user_code = normalize_code(raw_code)

    if not user_code or len(user_code) < 4 or len(user_code) > 32:
        flash("Code must be 4-32 characters using only A-Z, 0-9.")
        return redirect(url_for("index"))

    file_bytes = f.read()
    if not file_bytes or len(file_bytes) > app.config["MAX_CONTENT_LENGTH"]:
        flash("File empty or too large.")
        return redirect(url_for("index"))

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM files WHERE code = ?", (user_code,))
        if cur.fetchone():
            flash("That code is already in use. Choose a different code.")
            return redirect(url_for("index"))

        cur.execute(
            "INSERT INTO files (code, filename, mimetype, data) VALUES (?, ?, ?, ?)",
            (user_code, filename, f.mimetype or "application/octet-stream", file_bytes)
        )
        conn.commit()

    return render_template("upload_success.html", code=user_code, filename=filename)


@app.route("/receive", methods=["GET", "POST"])
def receive():
    ip = request.remote_addr or "unknown"
    if is_locked(ip):
        flash("Too many wrong codes from your IP. Try again in 1 hour.")
        return render_template("receive.html", file=None)

    file_record = None
    if request.method == "POST":
        code = normalize_code((request.form.get("code") or "").strip())
        if not code:
            flash("Please enter a code.")
            return render_template("receive.html", file=None)

        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, code, filename FROM files WHERE code = ?", (code,))
            row = cur.fetchone()

        if not row:
            update_attempts(ip, success=False)
            flash("Invalid code. You have 10 attempts per hour.")
            return render_template("receive.html", file=None)

        update_attempts(ip, success=True)
        file_record = {
            "id": row["id"],
            "code": row["code"],
            "filename": row["filename"]
        }

    return render_template("receive.html", file=file_record)


@app.route("/download/<int:file_id>/<code>")
def download(file_id, code):
    ip = request.remote_addr or "unknown"
    if is_locked(ip):
        return "Access locked for this IP. Try again in 1 hour.", 429

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT code, filename, mimetype, data FROM files WHERE id = ?", (file_id,))
        row = cur.fetchone()

        if not row:
            abort(404, "File not found.")

        if normalize_code(code) != row["code"]:
            update_attempts(ip, success=False)
            abort(403, "Invalid code for this file.")

        file_data = row["data"]
        filename = row["filename"]
        mimetype = row["mimetype"]

        cur.execute("INSERT INTO downloads (file_id, ip) VALUES (?, ?)", (file_id, ip))
        conn.commit()

    update_attempts(ip, success=True)

    if file_data:
        return send_file(
            BytesIO(file_data),
            as_attachment=True,
            download_name=filename,
            mimetype=mimetype,
            max_age=0,
            conditional=True
        )
    abort(500, "File data missing.")


# ---------- TIKTOK DOWNLOAD CORE (BEST VIDEO + AUDIO, ANY SIZE) ----------
def get_tiktok_opts(download_id):
    """
    Ask yt_dlp for best video+audio as MP4, any resolution/orientation.
    """
    return {
        "outtmpl": os.path.join(
            DOWNLOAD_FOLDER,
            f"tiktok_{download_id}_%(title).50s.%(ext)s"
        ),
        "format": "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best",
        "noplaylist": True,
        "merge_output_format": "mp4",
        "progress_hooks": [lambda d: tiktok_progress_hook(d, download_id)],
        "force_generic_extractor": False,
    }


def tiktok_progress_hook(d, download_id):
    status = d.get("status")
    if status == "downloading":
        total = d.get("total_bytes") or d.get("total_bytes_estimate") or 1
        downloaded = d.get("downloaded_bytes", 0)
        pct = int(downloaded / total * 100)
        download_progress[download_id] = max(0, min(pct, 99))
    elif status == "finished":
        download_progress[download_id] = 100


def download_video_thread(video_url, download_id):
    try:
        opts = get_tiktok_opts(download_id)
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(video_url, download=True)
            filename = ydl.prepare_filename(info)
        download_files[download_id] = filename
        download_progress[download_id] = 100
    except Exception as e:
        print("TikTok download error:", e)
        download_progress[download_id] = -1


@app.route("/start_import", methods=["POST"])
def start_import():
    video_url = request.form.get("video_url", "").strip()
    if not video_url:
        return jsonify({"error": "No URL"}), 400

    if "tiktok.com" not in video_url:
        return jsonify({"error": "Please provide a valid TikTok link"}), 400

    download_id = str(uuid.uuid4())
    download_progress[download_id] = 0
    download_files[download_id] = None

    threading.Thread(
        target=download_video_thread,
        args=(video_url, download_id),
        daemon=True
    ).start()

    return jsonify({"download_id": download_id})


@app.route("/progress/<download_id>")
def progress(download_id):
    percent = download_progress.get(download_id, 0)
    return jsonify({"percent": percent})



# ---------- ADMIN STATS ----------
@app.route("/admin/stats")
def admin_stats():
    with get_db() as conn:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as total FROM files")
        total_uploads = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM attempts WHERE count > 0")
        total_attempts = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM downloads")
        total_downloads = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM tiktok_downloads")
        total_tiktok_downloads = cur.fetchone()["total"]

        cur.execute("""
            SELECT ip, COUNT(*) as count FROM downloads
            GROUP BY ip ORDER BY count DESC LIMIT 10
        """)
        top_ips = [(row["ip"], row["count"]) for row in cur.fetchall()]

        cur.execute("""
            SELECT ip, COUNT(*) as count FROM tiktok_downloads
            GROUP BY ip ORDER BY count DESC LIMIT 10
        """)
        top_tiktok_ips = [(row["ip"], row["count"]) for row in cur.fetchall()]

    return render_template(
        "admin_stats.html",
        total_uploads=total_uploads,
        total_attempts=total_attempts,
        total_downloads=total_downloads,
        total_tiktok_downloads=total_tiktok_downloads,
        top_ips=top_ips,
        top_tiktok_ips=top_tiktok_ips,
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )



if __name__ == "__main__":
    # Run from backend folder:  cd backend && python app.py
    app.run(host="0.0.0.0", port=5000, debug=True)
