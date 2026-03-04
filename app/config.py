import os
from pathlib import Path


class Config:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    DB_PATH = str(PROJECT_ROOT / "database.db")
    DOWNLOAD_FOLDER = str(PROJECT_ROOT / "downloads")
    MEDIA_FOLDER = str(PROJECT_ROOT / "app" / "media")
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "MySecretPassword123"
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

    ALLOWED_EXTENSIONS = {
        "txt", "pdf", "png", "jpg", "jpeg", "gif",
        "zip", "rar", "7z", "mp4", "mp3", "mov",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "apk", "exe",
    }
    IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
    CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
