from flask import Flask

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS

from .server import mod
from werkzeug.contrib.fixers import ProxyFix
__version__ = '0.0.20'


def setup_app():
    app.config.from_object('neuroglancer_auth.config.Config')
    Session(app)
    CORS(app, expose_headers='WWW-Authenticate')

    print(app.secret_key)

    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.register_blueprint(mod)

    return app
