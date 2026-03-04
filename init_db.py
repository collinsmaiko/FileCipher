from app import create_app
from app.extensions import init_db


app = create_app()

with app.app_context():
    init_db()

print("database initialized")
