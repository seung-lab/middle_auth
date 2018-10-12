import secrets
import redis
# import google.oauth2.credentials
import google_auth_oauthlib.flow
# from google.oauth2 import id_token
from oauthlib import oauth2
import googleapiclient.discovery
# from google.auth.transport import requests
import flask
from neuroglancer_auth.redis_config import redis_config

__version__ = '0.0.7'
import os

mod = flask.Blueprint('auth', 'auth', url_prefix='/auth')
r = redis.Redis(
        host=redis_config['HOST'],
        port=redis_config['PORT'])

CLIENT_SECRETS_FILE = os.environ['OAUTH_CLIENT_SECRET']
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile']

@mod.route("/version")
def version():
    return "neuroglance_auth -- version " + __version__

@mod.route("/authorize")
def auth():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('auth.oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        prompt='consent')
    flask.session['state'] = state

    return flask.redirect(authorization_url)


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

    our_token = secrets.token_hex(16)

    r.setex(our_token, res['id'], 24 * 60 * 60)  # 24 hours

    return flask.jsonify(our_token)


@mod.route('/test')
def test_api_request():

    token = flask.request.headers.get(
        'authorization') or flask.request.args.get('token')

    id_bytes = r.get(token)

    if id_bytes:
        return flask.jsonify(int(id_bytes))
    else:
        return "invalid/expired token", 403

    return flask.jsonify(int(r.get(flask.request.args.get('token'))))
