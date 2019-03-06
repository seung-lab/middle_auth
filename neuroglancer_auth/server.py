import secrets
import redis
import google_auth_oauthlib.flow
from oauthlib import oauth2
import googleapiclient.discovery
import flask
from neuroglancer_auth.redis_config import redis_config

import uuid

__version__ = '0.0.13'
import os

mod = flask.Blueprint('auth', 'auth', url_prefix='/auth')
ws = flask.Blueprint('ws', 'ws', url_prefix='/auth');

sockets = {}

r = redis.Redis(
        host=redis_config['HOST'],
        port=redis_config['PORT'])

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile']

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
    resp = flask.Response("neuroglance_auth -- version " + __version__)
    resp.headers['Access-Control-Allow-Origin'] = 'http://localhost:8000'
    return resp

@mod.route("/oauth2callback")
def oauth2callback():
    print(dict(flask.session))

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

    our_token = secrets.token_hex(16)

    r.setex(our_token, 24 * 60 * 60, res['id']) # 24 hours

    socket = sockets.pop(flask.session['uuid'])
    socket.send(our_token)
    socket.close()

    return flask.jsonify("success")

@mod.route('/test')
def test_api_request():
    token = flask.request.headers.get('authorization')

    if not token.startswith('Bearer '):
        return "invalid/expired token", 403

    token = token.split(' ')[1] # remove schema

    id_bytes = r.get(token)

    if id_bytes:
        return flask.jsonify(int(id_bytes))
    else:
        return "invalid/expired token", 403

    return flask.jsonify(int(r.get(flask.request.args.get('token'))))
