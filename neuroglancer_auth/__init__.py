from flask import Flask

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS

from .server import api_v1, admin_site
from .model.base import db
from .model.user import User
from .model.api_key import APIKey


from werkzeug.contrib.fixers import ProxyFix
import redis # used in the envvar config

__version__ = '0.8.2'


def setup_app():
    app.config.from_envvar('AUTH_CONFIG_SETTINGS')
    Session(app)
    CORS(app, expose_headers=['WWW-Authenticate', 'X-Requested-With'])

    app.wsgi_app = ProxyFix(app.wsgi_app)

    with app.app_context():
        db.init_app(app)
        db.create_all()

    app.register_blueprint(api_v1)
    app.register_blueprint(admin_site)

    @app.before_first_request
    def initialize():
        existing_admin = User.get_by_email("chris@eyewire.org")
        
        if not existing_admin:
            User.create_account("chris@eyewire.org", "chris", admin=True, group_names=["default"])
        
        APIKey.load_into_cache()

    return app
