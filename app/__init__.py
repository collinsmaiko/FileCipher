import os

from flask import Flask

from app.config import Config
from app.extensions import init_db
from app.routes import ALL_BLUEPRINTS
from app.utils.security import set_security_headers


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(config_class)

    os.makedirs(app.config["DOWNLOAD_FOLDER"], exist_ok=True)

    with app.app_context():
        init_db()

    for blueprint in ALL_BLUEPRINTS:
        app.register_blueprint(blueprint)

    app.after_request(set_security_headers)

    return app
