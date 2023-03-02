from flask import Flask, blueprints

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS
from flaskext.markdown import Markdown
from flask_migrate import Migrate

from .server import blueprints, sticky_blueprints
from .model.base import db
from .model.user import User
from .model.api_key import APIKey

from .flask_admin import setup_admin

from werkzeug.middleware.proxy_fix import ProxyFix
import redis # used in the envvar config

__version__ = '2.22.2'

def setup_app():
    app.config.from_envvar('AUTH_CONFIG_SETTINGS')
    Session(app)
    CORS(app, expose_headers=['WWW-Authenticate', 'X-Requested-With'])
    Markdown(app)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    db.init_app(app)
    Migrate(app, db)

    if app.config.get('STICKY_AUTH',  False):
        setup_admin(app, db)

    bps = sticky_blueprints if app.config.get('STICKY_AUTH',  False) else blueprints

    for bp in bps:
        app.register_blueprint(bp)
    return app

@app.cli.command("initialize")
def initialize():
    default_admins = app.config.get('DEFAULT_ADMINS', [])

    for email, name, pi in default_admins:
        existing_user = User.get_by_email(email)

        if not existing_user:
            User.create_account(email, name, pi, admin=True, group_names=["default"])

    APIKey.load_into_cache()
