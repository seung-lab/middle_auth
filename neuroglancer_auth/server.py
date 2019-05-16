import flask
import secrets
import redis
import google_auth_oauthlib.flow
from oauthlib import oauth2
import googleapiclient.discovery
from neuroglancer_auth.redis_config import redis_config
import urllib
import uuid
import json
from functools import wraps
from flask_sqlalchemy import SQLAlchemy

__version__ = '0.0.20'
import os

mod = flask.Blueprint('auth', __name__, url_prefix='/auth')

r = redis.Redis(
        host=redis_config['HOST'],
        port=redis_config['PORT'])

db = SQLAlchemy()

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']

SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

AUTH_URI = os.environ.get('AUTH_URI', 'localhost:5000/auth')

@mod.route("/authorize")
def authorize():
    if flask.request.environ['HTTP_ORIGIN'] is None:
        return flask.Response("Invalid Request", 400)

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('auth.oauth2callback', _external=True, _scheme='https')
    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        prompt='consent')

    flask.session['state'] = state
    flask.session['redirect'] = flask.request.args.get('redirect')

    if not 'redirect' in flask.session:
        return flask.Response("Invalid Request", 400)

    resp = flask.Response(authorization_url)
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Origin'] = flask.request.environ['HTTP_ORIGIN']

    return resp

@mod.route("/version")
def version():
    return "neuroglance_auth -- version " + __version__

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    role_id = db.Column('role_id', db.Integer, db.ForeignKey("role.id"), nullable=False)

def get_user(email):
    return User.query.filter_by(email=email).first()

def get_user_and_roles(email):
    return User.query.filter_by(email=email).first()

def create_account(info):
    user = User(username=info['name'], email=info['email'])
    db.session.add(user)
    db.session.flush() # get inserted id

    role = UserRole(user_id=user.id, role_id=Role.query.filter_by(name="edit_all").first().id)
    db.session.add(role)

    db.session.commit()
    return user

@mod.route("/oauth2callback")
def oauth2callback():
    if not 'state' in flask.session:
        return flask.Response("Invalid Request", 400)

    if not 'redirect' in flask.session:
        return flask.Response("Invalid Request", 400)

    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('auth.oauth2callback', _external=True)

    authorization_response = flask.request.url

    try:
        flow.fetch_token(authorization_response=authorization_response)
    except oauth2.rfc6749.errors.InvalidGrantError as err:
        print("OAuth Error: {0}".format(err))
        return flask.jsonify("authorization error")

    credentials = flow.credentials

    info = googleapiclient.discovery.build('oauth2', 'v2',
                                          credentials=credentials).userinfo().v2().me().get().execute()

    user = get_user(info['email'])

    if user is None:
        user = create_account(info)

    our_token = None

    user_json = json.dumps({
        id: user.id,
        username: user.username,
        email: user.email,
    });

    # keep trying to insert a random token into redis until it finds one that is not already in use
    while True:
        our_token = secrets.token_hex(16)
        # nx = Only set the key if it does not already exist
        not_dupe = r.set(our_token, user_json, nx=True, ex=24 * 60 * 60) # 24 hours

        if not_dupe:
            break

    return flask.redirect(flask.session['redirect'] + '?token=' + our_token, code=302)

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = flask.request.headers.get('authorization')
        if not token:
            resp = flask.Response("Unauthorized", 401)
            resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '"'
            return resp
        elif not token.startswith('Bearer '):
            resp = flask.Response("Invalid Request", 400)
            resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '", error="invalid_request", error_description="Header must begin with \'Bearer\'"'
            return resp
        else:
            token = token.split(' ')[1] # remove schema
            cached_user_data = r.get(token)

            if cached_user_data:
                flask.g.user = json.loads(cached_user_data.decode('utf-8'))
                flask.g.token = token
                return f(*args, **kwargs)
            else:
                resp = flask.Response("Invalid/Expired Token", 401)
                resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '", error="invalid_token", error_description="Invalid/Expired Token"'
                return resp
    return decorated_function

@mod.route('/test')
@auth_required
def test_api_request():
    return flask.jsonify(flask.g.user)

@mod.route('/logout')
@auth_required
def logout():
    r.delete(flask.g.token)
    return flask.jsonify("success")
