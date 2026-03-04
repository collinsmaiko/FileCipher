import os
from pathlib import Path


class Config:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    DB_PATH = str(PROJECT_ROOT / "database.db")
    MEDIA_FOLDER = str(PROJECT_ROOT / "app" / "media")
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "MySecretPassword123"
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

    IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
    CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
