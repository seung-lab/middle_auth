import flask
import google_auth_oauthlib.flow
from oauthlib import oauth2
import googleapiclient.discovery
import urllib
import uuid
import json
from .model import db, User, Role, UserRole, APIKey, create_account, create_role, insert_and_generate_unique_token, delete_token
from middle_auth_client import auth_required, auth_requires_roles
import sqlalchemy
from furl import furl

from functools import wraps

__version__ = '0.0.30'
import os

mod = flask.Blueprint('auth', __name__, url_prefix='/auth')

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']

SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

@mod.route("/version")
def version():
    return "neuroglance_auth -- version fff origin: " + flask.request.environ.get('HTTP_ORIGIN', "no origin")

@mod.route("/authorize")
def authorize():
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
    
    cors_origin = flask.request.environ.get('HTTP_ORIGIN', None)

    programmatic_access = flask.request.headers.get('X-Requested-With') or cors_origin

    if programmatic_access:
        resp = flask.Response(authorization_url)

        if cors_origin:
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Access-Control-Allow-Origin'] = cors_origin

        return resp
    else:
        return flask.redirect(authorization_url, code=302)

@mod.route("/oauth2callback")
def oauth2callback():
    if not 'session' in flask.request.cookies:
        return flask.Response("Invalid Request, are third-party cookies enabled?", 400)

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

    user = User.get_by_email(info['email'])

    # TODO - detect if there are any differences (username) update the database

    if user is None:
        user = create_account(info['email'], info['name'], role_names=["edit_all"])

    user_json = json.dumps(user.create_cache())

    token = insert_and_generate_unique_token(user.id, user_json, ex=24 * 60 * 60) # 24 hours

    return flask.redirect(furl(flask.session['redirect']).add({'token': token}).url, code=302)

@mod.route('/test')
@auth_required
def test_api_request():
    return flask.jsonify(flask.g.auth_user)

@mod.route('/refresh_token')
@auth_required
def refresh_token():
    key = APIKey.generate(flask.g.auth_user['id'])
    return flask.jsonify(key)

@mod.route('/logout')
@auth_required
def logout():
    delete_token(flask.g.auth_user['id'], flask.g.auth_token)
    return flask.jsonify("success")

@mod.route('/role')
@auth_required
def get_all_roles():
    roles = Role().query.all()
    return flask.jsonify([role.as_dict() for role in roles])

@mod.route('/user')
@auth_requires_roles('admin')
def get_users_by_filter():
    email_filter = flask.request.args.get('email')

    if email_filter:
        users = User.search_by_email(email_filter)
        return flask.jsonify([user.as_dict() for user in users])

    return flask.Response([])

@mod.route('/user/<user_id>')
@auth_requires_roles('admin')
def get_user(user_id):
    user = User.get_by_id(int(user_id))

    if user:
        return flask.jsonify(user.create_cache())
    else:
        return flask.Response("User Doesn't exist", 404)

@mod.route('/user/<user_id>/role', methods=['POST'])
@auth_requires_roles('admin')
def user_roles(user_id):
    data = flask.request.json

    if data and 'role_id' in data:
        try:
            UserRole.add(int(user_id), data['role_id'])
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response("User already has role.", 422)
    else:
        return flask.Response("Missing role_id.", 400)

@mod.route('/user/<user_id>/role/<role_id>', methods=['DELETE'])
@auth_requires_roles('admin')
def remove_role(user_id, role_id):
    if Role.get_by_id(role_id).name == 'admin':
        return flask.Response("An admin cannot remove admin role from themself.", 422)

    UserRole.remove(int(user_id), int(role_id)) # no error possible? if user doesn't have role, just return success? should probably fail
    return flask.jsonify("success")

@mod.route('/role/<role_name>', methods=['POST', 'OPTIONS'])
@auth_requires_roles('admin')
def create_role_route(role_name):
    try:
        role = create_role(role_name)
        return flask.jsonify(role.id)
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("Role already exists.", 422)

@mod.route('/my_roles')
@auth_required
def get_roles():
    return flask.jsonify(User.get_by_id(flask.g.auth_user['id']).get_roles())

@mod.route('/admin/<path:path>')
def send_admin_files(path):
    return flask.send_from_directory('admin', path)