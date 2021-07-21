from flask import Flask

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS
from flaskext.markdown import Markdown
from flask_migrate import Migrate

from .server import version_bp, api_v1_bp, admin_site_bp
from .model.base import db
from .model.user import User
from .model.api_key import APIKey


from werkzeug.middleware.proxy_fix import ProxyFix
import redis # used in the envvar config

__version__ = '2.4.4'

def setup_app():
    app.config.from_envvar('AUTH_CONFIG_SETTINGS')
    Session(app)
    CORS(app, expose_headers=['WWW-Authenticate', 'X-Requested-With'])
    Markdown(app)

    app.wsgi_app = ProxyFix(app.wsgi_app)

    db.init_app(app)
    Migrate(app, db)

    app.register_blueprint(version_bp)
    app.register_blueprint(api_v1_bp)
    app.register_blueprint(admin_site_bp)

    return app

@app.cli.command("initialize")
def initialize():
    DEFAULT_ADMINS = [
        ["chris@eyewire.org", "Chris Jordan", "seung"],
        ["sven.dorkenwald@googlemail.com", "Sven Dorkenwald", "seung"]
    ]

    for email, name, pi in DEFAULT_ADMINS:
        existing_user = User.get_by_email(email)

        if not existing_user:
            User.create_account(email, name, pi, admin=True, group_names=["default"])

    APIKey.load_into_cache()
