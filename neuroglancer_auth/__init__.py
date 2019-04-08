import flask
from flask_sockets import Sockets
from flask_session import Session
from flask_cors import CORS

from .server import mod, ws
from werkzeug.contrib.fixers import ProxyFix
__version__ = '0.0.17'


def create_app():
    app = flask.Flask(__name__)
    app.config.from_object('neuroglancer_auth.config.Config')

    Session(app)
    CORS(app, expose_headers='WWW-Authenticate')

    print(app.secret_key)

    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.register_blueprint(mod)

    sockets = Sockets(app)
    sockets.register_blueprint(ws)

    return app
