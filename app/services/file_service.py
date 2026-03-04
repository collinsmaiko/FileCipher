from datetime import datetime, timedelta

from flask import current_app

from app.extensions import get_db


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def is_image_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["IMAGE_EXTENSIONS"]


def normalize_code(raw: str) -> str:
    alphabet = current_app.config["CODE_ALPHABET"]
    return "".join(ch for ch in raw.upper() if ch in alphabet)


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
            (ip, new_count, now.isoformat(), new_locked),
        )
        conn.commit()
