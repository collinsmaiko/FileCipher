from io import BytesIO

from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from app.extensions import get_db
from app.services.file_service import allowed_file, is_locked, normalize_code, update_attempts


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part in request.")
        return redirect(url_for("main.index"))

    file_obj = request.files["file"]
    if file_obj.filename == "":
        flash("No file selected.")
        return redirect(url_for("main.index"))

    filename = secure_filename(file_obj.filename)
    if not allowed_file(filename):
        flash("File type not allowed.")
        return redirect(url_for("main.index"))

    raw_code = (request.form.get("code") or "").strip()
    user_code = normalize_code(raw_code)

    if not user_code or len(user_code) < 4 or len(user_code) > 32:
        flash("Code must be 4-32 characters using only A-Z, 0-9.")
        return redirect(url_for("main.index"))

    file_bytes = file_obj.read()
    if not file_bytes:
        flash("File empty or too large.")
        return redirect(url_for("main.index"))

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM files WHERE code = ?", (user_code,))
        if cur.fetchone():
            flash("That code is already in use. Choose a different code.")
            return redirect(url_for("main.index"))

        cur.execute(
            "INSERT INTO files (code, filename, mimetype, data) VALUES (?, ?, ?, ?)",
            (user_code, filename, file_obj.mimetype or "application/octet-stream", file_bytes),
        )
        conn.commit()

    return render_template("upload_success.html", code=user_code, filename=filename)


@main_bp.route("/receive", methods=["GET", "POST"])
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
        file_record = {"id": row["id"], "code": row["code"], "filename": row["filename"]}

    return render_template("receive.html", file=file_record)


@main_bp.route("/download/<int:file_id>/<code>")
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

    if not file_data:
        abort(500, "File data missing.")

    return send_file(
        BytesIO(file_data),
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype,
        max_age=0,
        conditional=True,
    )
