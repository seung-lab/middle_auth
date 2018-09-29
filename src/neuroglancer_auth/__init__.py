import flask
from .server import mod
from werkzeug.contrib.fixers import ProxyFix
__version__ = 'v0.0.1'


def create_app():
    app = flask.Flask(__name__)

    app.config.from_object('neuroglancer_auth.config.Config')

    print(app.secret_key)

    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.register_blueprint(mod, url_prefix='/')
    return app
