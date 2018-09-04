import secrets

import redis

r = redis.Redis()

import google.oauth2.credentials
import google_auth_oauthlib.flow
from google.oauth2 import id_token
from oauthlib import oauth2
import googleapiclient.discovery
from google.auth.transport import requests


from werkzeug.contrib.fixers import ProxyFix

import flask
app = flask.Flask(__name__)

app.config.from_object('config.Config')

print(app.secret_key)

app.wsgi_app = ProxyFix(app.wsgi_app)

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/userinfo.profile']

@app.route("/")
def hello():
    return flask.url_for('oauth2callback', _external=True)

@app.route("/authorize")
def auth():
	flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
	flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
	authorization_url, state = flow.authorization_url(
		# Enable offline access so that you can refresh an access token without
		# re-prompting the user for permission. Recommended for web server apps.
		access_type='offline',
		# Enable incremental authorization. Recommended as a best practice.
		include_granted_scopes='true',
		prompt='consent')
	flask.session['state'] = state

	return flask.redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
	state = flask.session['state']

	flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
	flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

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

	r.setex(our_token, res['id'], 24 * 60 * 60) # 24 hours

	return flask.jsonify(our_token)


@app.route('/test')
def test_api_request():

	token = flask.request.headers.get('authorization') or flask.request.args.get('token')

	id_bytes = r.get(token)

	if id_bytes:
		return flask.jsonify(int(id_bytes))
	else:
		return "invalid/expired token", 403

	return flask.jsonify(int(r.get(flask.request.args.get('token'))))
