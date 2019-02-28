import flask
from flask_sockets import Sockets
from .server import mod, ws
from werkzeug.contrib.fixers import ProxyFix
__version__ = '0.0.13'


def create_app():
    app = flask.Flask(__name__)

    app.config.from_object('neuroglancer_auth.config.Config')

    print(app.secret_key)

    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.register_blueprint(mod)

    sockets = Sockets(app)
    sockets.register_blueprint(ws)

    return app
