from flask import Flask

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS

from .server import version_bp, api_v1_bp, admin_site_bp, test_bp
from .model.base import db
from .model.user import User
from .model.api_key import APIKey

from flask import Blueprint


from werkzeug.middleware.proxy_fix import ProxyFix
import redis # used in the envvar config

__version__ = '2.2.0'


from flask_restx import Api

DEFAULT_ADMINS = [
    ["chris@eyewire.org", "Chris Jordan", "seung"],
    ["sven.dorkenwald@googlemail.com", "Sven Dorkenwald", "seung"]
]

mybp = Blueprint('api', __name__, url_prefix='/auth/my')

def setup_app():
    app.config.from_envvar('AUTH_CONFIG_SETTINGS')

    # app.app_context().push()

    Session(app)
    CORS(app, expose_headers=['WWW-Authenticate', 'X-Requested-With'])

    app.wsgi_app = ProxyFix(app.wsgi_app)

    with app.app_context():
        db.init_app(app)
        db.create_all()
        api = Api(mybp, title="Boop", version=__version__)
        api.add_namespace(test_bp, path='/v2')
        app.register_blueprint(mybp)

    app.register_blueprint(version_bp)
    app.register_blueprint(api_v1_bp)
    app.register_blueprint(admin_site_bp)

    @app.before_first_request
    def initialize():
        for email, name, pi in DEFAULT_ADMINS:
            existing_user = User.get_by_email(email)

            if not existing_user:
                User.create_account(email, name, pi, admin=True, group_names=["default"])

        APIKey.load_into_cache()

    return app
