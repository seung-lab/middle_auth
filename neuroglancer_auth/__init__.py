from flask import Flask
from flask_uwsgi_websocket import GeventWebSocket
from flask_session import Session
from flask_cors import CORS

from .server import mod, setup_socket_route
from werkzeug.contrib.fixers import ProxyFix
__version__ = '0.0.16'


def create_app():
    app = Flask(__name__)
    app.config.from_object('neuroglancer_auth.config.Config')

    sockets = GeventWebSocket(app) # trying it here to see if this fixes the monkeypatch ssl issue

    Session(app)
    CORS(app, expose_headers='WWW-Authenticate')

    print(app.secret_key)

    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.register_blueprint(mod)

    ws = setup_socket_route(app)

    sockets.register_blueprint(ws)

    return app
