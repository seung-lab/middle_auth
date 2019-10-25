import flask
import google_auth_oauthlib.flow
from oauthlib import oauth2
import googleapiclient.discovery
import urllib
import uuid
import json
from middle_auth_client import auth_required, auth_requires_admin, auth_requires_permission
import sqlalchemy
from furl import furl

from .model.user import User
from .model.api_key import APIKey, insert_and_generate_unique_token, delete_token, delete_all_tokens_for_user
from .model.dataset_admin import DatasetAdmin
from .model.group import Group
from .model.user_group import UserGroup
from .model.dataset import Dataset
from .model.group_dataset import GroupDataset

import os

from functools import wraps

__version__ = '0.8.1'
import os

mod = flask.Blueprint('auth', __name__, url_prefix='/auth')

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

def requires_dataset_admin(f):
    @wraps(f)
    @auth_required
    def decorated_function(dataset_id, *args, **kwargs):
        is_dataset_admin = flask.g.auth_user['admin'] or DatasetAdmin.is_dataset_admin(flask.g.auth_user['id'], dataset_id)
        
        if is_dataset_admin:
            return f(*args, **{**kwargs, **{'dataset_id': dataset_id}})
        else:
            return flask.Response("Requires dataset admin privilege.", 403)

    return decorated_function

def requires_group_admin(f):
    @wraps(f)
    @auth_required
    def decorated_function(group_id, *args, **kwargs):
        is_group_admin = flask.g.auth_user['admin'] or UserGroup.is_group_admin(flask.g.auth_user['id'], group_id)

        if is_group_admin:
            return f(*args, **{**kwargs, **{'group_id': group_id}})
        else:
            return flask.Response("Requires group admin privilege.", 403)

    return decorated_function

def requires_some_admin(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        is_an_admin = (flask.g.auth_user['admin']
            or DatasetAdmin.is_dataset_admin_any(flask.g.auth_user['id'])
            or UserGroup.is_group_admin_any(flask.g.auth_user['id']))

        if is_an_admin:
            return f(*args, **kwargs)
        else:
            resp = flask.Response("Requires admin privilege.", 403)
            return resp

    return decorated_function

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

    print("flask.session sid: {0}".format(flask.session.sid))
    print("flask.session state: {0}".format(flask.session['state']))

    flask.session['redirect'] = flask.request.args.get('redirect')

    if not 'redirect' in flask.session:
        return flask.Response("Invalid Request", 400)
    
    cors_origin = flask.request.environ.get('HTTP_ORIGIN', None)
    programmatic_access = flask.request.headers.get('X-Requested-With') or cors_origin

    if cors_origin:
        print("has cors_origin")
    else:
        print("no cors_origin")

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
    
    return flask.jsonify(flask.session.sid)

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
        user = User.create_account(info['email'], info['name'], False, group_names=["default"])
    else:
        user.update({'name': info['name']})

    user_json = json.dumps(user.create_cache())

    token = insert_and_generate_unique_token(user.id, user_json, ex=7 * 24 * 60 * 60) # 7 days

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

@mod.route('/logout_all')
@auth_required
def logout_all():
    delete_all_tokens_for_user(flask.g.auth_user['id'])
    return flask.jsonify("success")

@mod.route('/user')
@requires_some_admin
def get_users_by_filter():
    users = None

    if flask.request.args.get('id'):
        users = User.filter_by_ids([int(x) for x in flask.request.args.get('id').split(',') if x])
    elif flask.request.args.get('email'):
        users = User.search_by_email(flask.request.args.get('email'))
    elif flask.request.args.get('name'):
        users = User.search_by_name(flask.request.args.get('name'))
    else:
        users = User.query.all()
    return flask.jsonify([user.as_dict() for user in users])

@mod.route('/user', methods=['POST'])
@requires_some_admin
def create_user_route():
    data = flask.request.json

    if not (data and 'name' in data):
        return flask.Response("Missing name.", 400)
    
    if not (data and 'email' in data):
        return flask.Response("Missing email.", 400)

    try:
        user = User.create_account(data['email'], data['name'], False, group_names=["default"])
        return flask.jsonify(user.as_dict())
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("User with email already exists.", 422)

@mod.route('/user/me')
@auth_required
def get_self():
    user = User.get_by_id(flask.g.auth_user['id'])

    if user:
        return flask.jsonify(user.as_dict())
    else:
        return flask.Response("Error finding user", 500)

@mod.route('/user/<int:user_id>')
@requires_some_admin
def get_user(user_id):
    user = User.get_by_id(user_id)

    if user:
        return flask.jsonify(user.as_dict())
    else:
        return flask.Response("User doesn't exist", 404)

@mod.route('/user/<int:user_id>', methods=['PUT'])
@auth_requires_admin
def modify_user_route(user_id):
    data = flask.request.json

    if data and 'admin' in data and flask.g.auth_user['id'] == user_id:
        return flask.Response("Cannot remove admin permissions from yourself.", 403)

    user = User.get_by_id(user_id)

    if user:
        user.update(data)
        return flask.jsonify("success")
    else:
        return flask.Response("User doesn't exist", 404)

    if data and 'admin' in data:
        try:
            group = Group.add(data['name'])
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response("Group already exists.", 422)
    else:
        return flask.Response("Missing name.", 400)

@mod.route('/user/<int:user_id>/group')
@requires_some_admin
def get_user_groups(user_id):
    user = User.get_by_id(user_id)

    if user:
        groups = user.get_groups()
        return flask.jsonify(groups)
    else:
        return flask.Response("User doesn't exist", 404)

@mod.route('/user/<int:user_id>/permissions')
@auth_requires_admin
def get_user_permissions(user_id):
    user = User.get_by_id(user_id)

    if user:
        permissions = user.get_permissions()
        return flask.jsonify(permissions)
    else:
        return flask.Response("User doesn't exist", 404)

@mod.route('/dataset', methods=['GET'])
@auth_required
def get_all_datasets():
    datasets = []

    if flask.g.auth_user['admin']:
        datasets = Dataset.query.all()
    else:
        datasets = DatasetAdmin.get_all_by_admin(flask.g.auth_user['id'])

    return flask.jsonify([dataset.as_dict() for dataset in datasets])

@mod.route('/dataset', methods=['POST'])
@auth_requires_admin
def create_dataset_route():
    data = flask.request.json

    if data and 'name' in data:
        try:
            dataset = Dataset.add(data['name'])
            return flask.jsonify(dataset.as_dict())
        except sqlalchemy.exc.IntegrityError as err:
            return flask.make_response(flask.jsonify("Dataset already exists."), 422)
    else:
        return flask.Response("Missing name.", 400)

@mod.route('/dataset/<int:dataset_id>', methods=['GET'])
@requires_dataset_admin
def get_dataset(dataset_id):
    dataset = Dataset.get_by_id(dataset_id)

    if dataset:
        return flask.jsonify(dataset.as_dict())
    else:
        return flask.Response("Dataset doesn't exist", 404)

@mod.route('/dataset/<int:dataset_id>/admin', methods=['GET'])
@requires_dataset_admin
def get_dataset_admins(dataset_id):
    admins = DatasetAdmin.get_all_by_dataset(dataset_id)
    return flask.jsonify(admins)

@mod.route('/dataset/<int:dataset_id>/admin', methods=['POST'])
@requires_dataset_admin
def add_admin_to_dataset(dataset_id):
    data = flask.request.json

    if data and 'user_id' in data:
        try:
            DatasetAdmin.add(data['user_id'], dataset_id)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Resaponse("User is already an admin of this dataset.", 422)
    else:
        return flask.Response("Missing user_id.", 400)

@mod.route('/dataset/<int:dataset_id>/admin/<int:user_id>', methods=['DELETE'])
@auth_requires_admin
def remove_admin_from_dataset(dataset_id, user_id):
    DatasetAdmin.remove(user_id=user_id, dataset_id=dataset_id)
    return flask.jsonify("success")

@mod.route('/dataset/<int:dataset_id>/group', methods=['GET'])
@requires_dataset_admin
def get_all_groups_for_dataset(dataset_id): # nearly identical to get_datasets_from_group_route
    permissions = GroupDataset.get_all_group_permissions(dataset_id)
    return flask.jsonify(permissions)

@mod.route('/dataset/<int:dataset_id>/group', methods=['POST'])
@requires_dataset_admin
def add_dataset_to_group_route(dataset_id):
    data = flask.request.json

    if data and 'group_id' in data:
        level = data.get('level', 0)

        if level > 2:
            return flask.make_response(flask.jsonify("Invalid level: {0}".format(level)), 400)

        try:
            GroupDataset.add(dataset_id=dataset_id, group_id=int(data['group_id']), level=level)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.make_response(flask.jsonify("Dataset already includes group."), 422)
    else:
        return flask.make_response(flask.jsonify("Missing group_id."), 400)

@mod.route('/dataset/<int:dataset_id>/group/<int:group_id>', methods=['PUT'])
@requires_dataset_admin
def update_dataset_to_group_route(dataset_id, group_id):
    data = flask.request.json

    if data:
        try:
            gd = GroupDataset.query.filter_by(group_id=group_id, dataset_id=int(dataset_id)).first()

            if gd:
                gd.update(data.get('level', 0))
                return flask.jsonify("success")
            else:
                return flask.Response("Dataset doesn't exist for this group", 404)
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response("Group already contains dataset.", 422)
    else:
        return flask.Response("Missing data.", 400)

@mod.route('/dataset/<int:dataset_id>/group/<int:group_id>', methods=['DELETE'])
@requires_dataset_admin
def remove_dataset_to_group_route(dataset_id, group_id):
    GroupDataset.remove(group_id=group_id, dataset_id=int(dataset_id)) # TODO return error if group doesn't exist
    return flask.jsonify("success")

@mod.route('/group', methods=['GET'])
@auth_required
def get_all_groups():    
    groups = Group.search_by_name(flask.request.args.get('name'))
    return flask.jsonify([group.as_dict() for group in groups])

@mod.route('/group', methods=['POST'])
@requires_some_admin
def create_group_route():
    data = flask.request.json

    if data and 'name' in data:
        try:
            group = Group.add(data['name'])
            UserGroup.add(flask.g.auth_user['id'], group.id, True)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response("Group already exists.", 422)
    else:
        return flask.Response("Missing name.", 400)

@mod.route('/group/<int:group_id>', methods=['GET'])
@requires_some_admin
def get_group(group_id):
    group = Group.get_by_id(group_id)

    if group:
        return flask.jsonify(group.as_dict())
    else:
        return flask.Response("Group doesn't exist", 404)

@mod.route('/group/<int:group_id>/dataset', methods=['GET'])
@requires_some_admin
def get_datasets_from_group_route(group_id):
    permissions = GroupDataset.get_permissions_for_group(group_id)
    return flask.jsonify(permissions)

@mod.route('/group/<int:group_id>/user', methods=['GET'])
@requires_some_admin
def get_users_for_group_route(group_id):
    # todo, we should check to see if the group is valid before checking for users
    users = UserGroup.get_users(group_id)
    return flask.jsonify(users)

@mod.route('/group/<int:group_id>/admin', methods=['GET'])
@requires_some_admin
def get_admins_for_group_route(group_id):
    # todo, we should check to see if the group is valid before checking for users
    users = UserGroup.get_admins(group_id)
    return flask.jsonify(users)

@mod.route('/group/<int:group_id>/user', methods=['POST'])
@requires_group_admin
def add_user_to_group_route(group_id):
    data = flask.request.json

    if data and 'user_id' in data:
        try:
            UserGroup.add(data['user_id'], group_id)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response("User already belongs to group.", 422)
    else:
        return flask.Response("Missing user_id.", 400)

@mod.route('/group/<int:group_id>/user/<int:user_id>', methods=['PUT'])
@auth_requires_admin
def modify_user_in_group_route(group_id, user_id):
    data = flask.request.json

    usergroup = UserGroup.get(group_id, user_id)

    if usergroup:
        usergroup.update(data)
        return flask.jsonify("success")
    else:
        return flask.Response("User doesn't belong to group", 404)

@mod.route('/group/<int:group_id>/user/<int:user_id>', methods=['DELETE'])
@requires_group_admin
def remove_user_from_group_route(group_id, user_id):
    ug = UserGroup.get(group_id, user_id)

    if not ug:
        return flask.Response("User doesn't belong to group", 404)

    if ug.admin and not flask.g.auth_user['admin']:
        return flask.Response("Only superadmins can remove group admins.", 403)

    ug.delete()
    return flask.jsonify("success")

@mod.route('/my_permissions')
@auth_required
def get_permissions():
    return flask.jsonify(User.get_by_id(flask.g.auth_user['id']).get_permissions())

@mod.route('/admin/<path:path>')
def send_admin_files(path):
    return flask.send_from_directory('admin', path)
