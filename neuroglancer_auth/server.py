import flask
import secrets
import redis
import google_auth_oauthlib.flow
from oauthlib import oauth2
import googleapiclient.discovery
from neuroglancer_auth.redis_config import redis_config
import urllib
import uuid
from functools import wraps

__version__ = '0.0.15'
import os

mod = flask.Blueprint('auth', __name__, url_prefix='/auth')
ws = flask.Blueprint('ws', __name__, url_prefix='/auth');

sockets = {}

r = redis.Redis(
        host=redis_config['HOST'],
        port=redis_config['PORT'])

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile']

AUTH_URI = os.environ.get('AUTH_URI', 'localhost:5000/auth')

@ws.route('/authorize')
def ws_auth(socket):
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
    flask.session['uuid'] = uuid.uuid4()
    sockets[flask.session['uuid']] = socket
    socket.send(authorization_url)
    flask.current_app.save_session(flask.session, flask.make_response(""))

    while not socket.closed:
        message = socket.receive()

@mod.route("/version")
def version():
    return "neuroglance_auth -- version " + __version__

@mod.route("/establish_session")
def establish_session():
    url_encoded_origin = flask.request.args.get('origin')

    if not url_encoded_origin:
        return "missing origin", 400

    resp = flask.Response("neuroglance_auth -- version " + __version__)
    resp.headers['Access-Control-Allow-Origin'] = urllib.parse.unquote(url_encoded_origin)
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp

@mod.route("/oauth2callback")
def oauth2callback():
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

    res = googleapiclient.discovery.build('oauth2', 'v2',
                                          credentials=credentials).userinfo().v2().me().get().execute()

    our_token = None

    # keep trying to insert a random token into redis until it finds one that is not already in use
    while True:
        our_token = secrets.token_hex(16)
        not_dupe = r.set(our_token, res['id'], nx=True, ex=24 * 60 * 60) # 24 hours

        if not_dupe:
            break

    socket = sockets.pop(flask.session['uuid'])
    socket.send(our_token)
    socket.close()

    return flask.jsonify("success")

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
            id_bytes = r.get(token)

            if id_bytes:
                flask.g.user_id = int(id_bytes)
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
    return flask.jsonify(flask.g.user_id)

@mod.route('/logout')
@auth_required
def logout():
    r.delete(flask.g.token)
    return flask.jsonify("success")
