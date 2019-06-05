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
from .model import db, User, Role, UserRole, APIKey
from middle_auth_client import auth_required, auth_requires_roles
import sqlalchemy

from functools import wraps

__version__ = '0.0.24'
import os

mod = flask.Blueprint('auth', __name__, url_prefix='/auth')

r = redis.Redis(
        host=redis_config['HOST'],
        port=redis_config['PORT'])

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']

SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

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

def generate_hash():
    return secrets.token_hex(16)

# load api keys into cache if they don't already exist in redit
# i.e. new deployment or some redis failure
def load_api_keys():
    api_keys = APIKey().query.all()

    for api_key in api_keys:
        user = get_user_by_id(api_key.user_id)
        r.set("token_" + api_key.key, json.dumps(create_cache_for_user(user)), nx=True)

def generate_api_key(user_id):
    entry = APIKey.query.filter_by(user_id=user_id).first()

    new_entry = not entry

    if not entry:
        entry = APIKey(user_id=user_id, key="")

    user = get_user_by_id(user_id)
    user_json = json.dumps(create_cache_for_user(user));
    token = insert_and_generate_unique_token(user_id, user_json)

    if not new_entry:
        delete_token(user_id, entry.key)

    entry.key = token

    if new_entry:
        db.session.add(entry)

    db.session.commit()

    return token

def get_user_by_id(id):
    return User.query.filter_by(id=id).first()

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

def get_roles_for_user(user_id):
    query = db.session.query(Role.name)\
        .join(UserRole, UserRole.role_id == Role.id)\
        .filter(UserRole.user_id == user_id)

    print(query.statement.compile(compile_kwargs={"literal_binds": True}))
    
    roles = query.all()

    return [val for val, in roles]

def create_role(role_name):
    role = Role(name=role_name)
    db.session.add(role)
    db.session.commit() # get inserted id
    return role

def create_account(info):
    user = User(username=info['name'], email=info['email'])
    db.session.add(user)
    db.session.flush() # get inserted id

    role = UserRole(user_id=user.id, role_id=Role.query.filter_by(name="edit_all").first().id)
    db.session.add(role)

    db.session.commit()
    return user

def create_cache_for_user(user):
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'roles': get_roles_for_user(user.id),
    }

def update_cache(user_id):
    user = User.query.filter_by(id=user_id).first()
    user_json = json.dumps(create_cache_for_user(user));

    tokens = r.smembers("userid_" + str(user_id))

    for token_bytes in tokens:
        token = token_bytes.decode('utf-8')
        ttl = r.ttl("token_" + token) # update token without changing ttl

        # ttl should never be -1 (no expiration)
        if ttl > -1:
            r.set("token_" + token, user_json, nx=False, ex=ttl)
        elif ttl == -2: # doesn't exist (expired)
            r.srem("userid_" + str(user_id), token)

def insert_and_generate_unique_token(user_id, value, ex=None):
    token = None

    # keep trying to insert a random token into redis until it finds one that is not already in use
    while True:
        token = generate_hash()
        # nx = Only set the key if it does not already exist
        not_dupe = r.set("token_" + token, value, nx=True, ex=ex)

        if not_dupe:
            break

    r.sadd("userid_" + str(user_id), token)

    return token

def delete_token(user_id, token):
    p = r.pipeline()
    p.delete("token_" + token)
    p.srem("userid_" + str(user_id), token)
    p.execute()

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

    user = get_user_by_email(info['email'])

    # TODO - detect if there are any differences (username) update the database it is?

    if user is None:
        user = create_account(info)

    user_json = json.dumps(create_cache_for_user(user));

    token = insert_and_generate_unique_token(user.id, user_json, ex=24 * 60 * 60) # 24 hours

    return flask.redirect(flask.session['redirect'] + '?token=' + token, code=302)

@mod.route('/test')
@auth_required
def test_api_request():
    return flask.jsonify(flask.g.auth_user)

@mod.route('/get_roles')
@auth_required
def get_roles():
    return flask.jsonify(get_roles_for_user(flask.g.auth_user['id']))

@mod.route('/get_all_roles')
@auth_required
def get_all_roles():
    roles = Role().query.all()
    return flask.jsonify([role.as_dict() for role in roles])

@mod.route('/add_role/<user_id>/<role_id>')
@auth_requires_roles('admin')
def add_role(user_id, role_id):
    user_id = int(user_id)
    role_id = int(role_id)
    role = UserRole(user_id=user_id, role_id=role_id)
    db.session.add(role)
    db.session.commit()

    update_cache(user_id)

    return flask.jsonify(get_roles_for_user(flask.g.auth_user['id']))

@mod.route('/remove_role/<user_id>/<role_id>')
@auth_requires_roles('admin')
def remove_role(user_id, role_id):
    UserRole.query.filter_by(user_id=user_id, role_id=role_id).delete()
    db.session.commit()

    update_cache(user_id)

    return flask.jsonify("success")

@mod.route('/create_role/<role_name>')
@auth_requires_roles('admin')
def create_role_route(role_name):
    try:
        role = create_role(role_name)
        return flask.jsonify(role.id)
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("Role already exists.", 422)

@mod.route('/refresh_token')
@auth_required
def refresh_token():
    key = generate_api_key(flask.g.auth_user['id'])
    return flask.jsonify(key)

@mod.route('/admin_panel')
@auth_requires_roles('admin', 'boop')
def admin_panel():
    return flask.jsonify("hello admin 3")

@mod.route('/logout')
@auth_required
def logout():
    delete_token(flask.g.auth_user['id'], flask.g.auth_token)
    return flask.jsonify("success")
