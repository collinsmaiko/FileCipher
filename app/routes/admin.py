from datetime import datetime

from flask import Blueprint, render_template

from app.extensions import get_db


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/stats")
def stats():
    with get_db() as conn:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as total FROM files")
        total_uploads = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM attempts WHERE count > 0")
        total_attempts = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) as total FROM downloads")
        total_downloads = cur.fetchone()["total"]

        cur.execute(
            """
            SELECT ip, COUNT(*) as count FROM downloads
            GROUP BY ip ORDER BY count DESC LIMIT 10
            """
        )
        top_ips = [(row["ip"], row["count"]) for row in cur.fetchall()]

    return render_template(
        "admin_stats.html",
        total_uploads=total_uploads,
        total_attempts=total_attempts,
        total_downloads=total_downloads,
        top_ips=top_ips,
        now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )
