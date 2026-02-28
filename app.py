import os
import sqlite3
import secrets
import yt_dlp
import glob
import threading
import time
import string
import uuid
from datetime import datetime, timedelta
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, abort, jsonify
)
from werkzeug.utils import secure_filename

DB_PATH = "database.db"

# ------------ SECURITY CONFIG ------------
app = Flask(__name__)

# Strong secret key for sessions (for production, set via env var)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Admin password for stats page
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "MySecretPassword123"

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

# ---------- downloads table ----------
def create_downloads_table():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            ip TEXT,
            downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Call it once at startup
create_downloads_table()


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


# @app.route("/download/<int:file_id>/<code>")
# def download(file_id, code):
#     ip = request.remote_addr or "unknown"

#     if is_locked(ip):
#         return "Access locked for this IP. Try again in 1 hour.", 429

#     conn = get_db()
#     cur = conn.cursor()
#     cur.execute(
#         "SELECT code, filename, mimetype, data FROM files WHERE id = ?",
#         (file_id,),
#     )
#     row = cur.fetchone()
#     conn.close()

#     if not row:
#         abort(404, description="File not found.")

#     if row["code"] != code.upper():
#         update_attempts(ip, success=False)
#         abort(403, description="Invalid code for this file.")

#     update_attempts(ip, success=True)

#     return send_file(
#         BytesIO(row["data"]),
#         as_attachment=True,
#         download_name=row["filename"],
#         mimetype=row["mimetype"],
#         max_age=0,
#         conditional=True,
#     )


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

    if not row:
        conn.close()
        abort(404, description="File not found.")

    if row["code"] != code.upper():
        conn.close()
        update_attempts(ip, success=False)
        abort(403, description="Invalid code for this file.")

    # ✅ Log successful download
    cur.execute(
        "INSERT INTO downloads (file_id, ip) VALUES (?, ?)",
        (file_id, ip)
    )
    conn.commit()
    conn.close()

    update_attempts(ip, success=True)

    return send_file(
        BytesIO(row["data"]),
        as_attachment=True,
        download_name=row["filename"],
        mimetype=row["mimetype"],
        max_age=0,
        conditional=True,
    )


@app.route("/admin/stats")
def admin_stats():
    conn = get_db()
    cur = conn.cursor()

    # Existing stats
    cur.execute("SELECT COUNT(*) FROM files")
    total_uploads = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM attempts")
    total_attempts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM downloads")
    total_downloads = cur.fetchone()[0]

    cur.execute("""
        SELECT ip, COUNT(*) as cnt FROM downloads
        GROUP BY ip ORDER BY cnt DESC LIMIT 5
    """)
    top_ips = [(row["ip"], row["cnt"]) for row in cur.fetchall()]

    # NEW: TikTok stats
    cur.execute("SELECT COUNT(*) FROM tiktok_downloads")
    total_tiktok_downloads = cur.fetchone()[0]

    cur.execute("""
        SELECT ip, COUNT(*) as cnt FROM tiktok_downloads
        GROUP BY ip ORDER BY cnt DESC LIMIT 5
    """)
    top_tiktok_ips = [(row["ip"], row["cnt"]) for row in cur.fetchall()]

    conn.close()

    return render_template(
        "admin_stats.html",
        total_uploads=total_uploads,
        total_attempts=total_attempts,
        total_downloads=total_downloads,
        top_ips=top_ips,
        total_tiktok_downloads=total_tiktok_downloads,
        top_tiktok_ips=top_tiktok_ips,
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )


DOWNLOAD_FOLDER = "downloads"
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# Store progress by a temporary key
download_progress = {}
download_files ={}


def download_video_thread(video_url, download_id):
    try:
        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, "%(title)s.%(ext)s"),
            "format": "mp4",
            "noplaylist": True,
            "progress_hooks": [lambda d: download_progress.update({
                download_id: int(d.get('downloaded_bytes',0)/max(1,d.get('total_bytes',1))*100)
            }) if d['status']=='downloading' else download_progress.update({download_id:100})],
            "force_generic_extractor": True
        }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(video_url, download=True)
            filename = ydl.prepare_filename(info)
            download_files[download_id] = filename
    except Exception as e:
        download_progress[download_id] = -1  # error



@app.route("/start_import", methods=["POST"])
def start_import():
    video_url = request.form.get("video_url")
    if not video_url:
        return jsonify({"error":"No URL"}),400

    download_id = str(uuid.uuid4())
    download_progress[download_id] = 0
    threading.Thread(target=download_video_thread, args=(video_url, download_id)).start()
    return jsonify({"download_id": download_id})

@app.route("/progress/<download_id>")
def progress(download_id):
    percent = download_progress.get(download_id, 0)
    return jsonify({"percent": percent})

@app.route("/download_file/<int:download_id>")
def download_file(download_id):
    """
    Unified download route for:
    1. Regular files stored in `download_files` dict or DB
    2. TikTok downloaded files tracked in `tiktok_download_temp`
    """
    ip = request.remote_addr or "unknown"

    # ----------- Check regular files first -----------
    path = download_files.get(str(download_id))  # make sure key is string if using dict
    if path:
        return send_file(path, as_attachment=True)

    # ----------- Check TikTok downloads -----------
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT video_url, local_path FROM tiktok_download_temp WHERE id = ?",
        (download_id,)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        abort(404, description="File or video not found.")

    video_url, local_path = row["video_url"], row["local_path"]

    # Log TikTok download
    cur.execute(
        "INSERT INTO tiktok_downloads (video_url, ip) VALUES (?, ?)",
        (video_url, ip)
    )
    conn.commit()
    conn.close()

    return send_file(local_path, as_attachment=True)


@app.route("/import", methods=["GET", "POST"])
def import_video():
    if request.method == "POST":
        video_url = request.form.get("video_url", "").strip()
        if not video_url:
            return render_template("import_video.html", error="Please enter a valid TikTok link.")

        # Strip query parameters
        from urllib.parse import urlparse
        parsed = urlparse(video_url)
        video_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Unique ID for this download
        download_id = str(uuid.uuid4())
        download_progress[download_id] = 0

        def progress_hook(d):
            if d['status'] == 'downloading':
                total_bytes = d.get('total_bytes') or d.get('total_bytes_estimate')
                downloaded = d.get('downloaded_bytes', 0)
                if total_bytes:
                    download_progress[download_id] = int(downloaded / total_bytes * 100)
            elif d['status'] == 'finished':
                download_progress[download_id] = 100

        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, "%(title)s.%(ext)s"),
            "format": "mp4",
            "noplaylist": True,
            "http_chunk_size": 0,
            "compat_opts": ["no-keep-fragments"],
            "force_generic_extractor": True,
            "progress_hooks": [progress_hook]
        }

        # Run yt-dlp synchronously (for demo) — in production use background thread
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(video_url, download=True)
                filename = ydl.prepare_filename(info)
        except Exception as e:
            return render_template("import_video.html", error=f"Failed to download video. {e}")

        # Once done, serve file
        return send_file(filename, as_attachment=True)

    return render_template("import_video.html")

def cleanup_downloads():
    now = time.time()
    for f in glob.glob("downloads/*"):
        if os.stat(f).st_mtime < now - 3600:  # older than 1 hour
            os.remove(f)


def create_tiktok_downloads_table():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tiktok_downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            video_url TEXT,
            ip TEXT,
            downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Call it once at startup
create_tiktok_downloads_table()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=tuple)
