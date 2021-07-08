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
from .model.api_key import APIKey, delete_token, delete_all_temp_tokens_for_user
from .model.dataset_admin import DatasetAdmin
from .model.group import Group
from .model.user_group import UserGroup
from .model.dataset import Dataset
from .model.group_dataset_permission import GroupDatasetPermission
from .model.app import App
from .model.cell_temp import CellTemp
from .model.tos import Tos
from .model.user_tos import UserTos
from .model.permission import Permission

import os

from functools import wraps

__version__ = '2.3.2'

print(f'flask version: {flask.__version__}')

TOKEN_NAME = os.environ.get('TOKEN_NAME', "middle_auth_token")
URL_PREFIX = os.environ.get('URL_PREFIX', 'auth')
AUTH_URI = os.environ.get('AUTH_URI', 'localhost:5000/auth') #deprecated
AUTH_URL = os.environ.get('AUTH_URL', AUTH_URI)
STICKY_AUTH_URL = os.environ.get('STICKY_AUTH_URL', AUTH_URL)

version_bp = flask.Blueprint('version_bp', __name__, url_prefix='/' + URL_PREFIX)

@version_bp.route("/version")
def version():
    return "neuroglance_auth -- version " + __version__

api_v1_bp = flask.Blueprint('api_v1_bp', __name__, url_prefix='/' + URL_PREFIX + '/api/v1')
admin_site_bp = flask.Blueprint('admin_site_bp', __name__, url_prefix='/' + URL_PREFIX + '/admin')

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

@api_v1_bp.route("/authorize", methods=['GET', 'POST'])
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('api_v1_bp.oauth2callback', _external=True, _scheme='https')
    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        prompt='consent')

    flask.session['state'] = state
    flask.session['redirect'] = flask.request.args.get('redirect')

    if flask.request.method == 'POST':
        flask.session['tos_agree'] = flask.request.form.get('tos_agree') == 'true'

    cors_origin = flask.request.environ.get('HTTP_ORIGIN')
    programmatic_access = flask.request.headers.get('X-Requested-With')# or cors_origin

    if programmatic_access:
        resp = flask.Response(authorization_url)

        if cors_origin:
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Access-Control-Allow-Origin'] = cors_origin

        return resp
    else:
        return flask.redirect(authorization_url, code=302)

DEFAULT_LOGIN_TOKEN_LENGTH = 7 * 24 * 60 * 60 # 7 days

def generatePostMessageResponse(token, app_urls):
    return f"""<script type="text/javascript">
        if (window.opener) {{
            window.opener.postMessage({{token: "{token}", app_urls: {app_urls}}}, "*");
        }}
        </script>"""

def finish_auth_flow(user):
    token = user.generate_token(ex=DEFAULT_LOGIN_TOKEN_LENGTH)

    redirect = flask.session.get('redirect')

    if redirect:
        return flask.redirect(furl(redirect)
            .add({TOKEN_NAME: token, 'middle_auth_url': STICKY_AUTH_URL})
            .add({'token': token}) # deprecated
            .url, code=302)
    else:
        app_urls = [app['url'] for app in App.get_all_dict()]
        return generatePostMessageResponse(token, app_urls)

@api_v1_bp.route("/oauth2callback")
def oauth2callback():
    if not 'session' in flask.request.cookies:
        return flask.Response("Invalid Request, are third-party cookies enabled?", 400)

    if not 'state' in flask.session:
        return flask.Response("Invalid Request", 400)

    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('api_v1_bp.oauth2callback', _external=True)

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

    if user is None or not user.gdpr_consent:
        if flask.session.get('tos_agree'):
            if user:
                user.update({
                    'name': info['name'],
                    'gdpr_consent': True,
                })
            else:
                user = User.create_account(info['email'], info['name'], None, False, True, group_names=["default"])
        else:
            flask.session['user_info'] = info
            return flask.send_from_directory('gdpr', 'consent.html')
    else:
        user.update({'name': info['name']})

    return finish_auth_flow(user)

@api_v1_bp.route("/register", methods=['POST'])
def register():
    info = flask.session.pop('user_info', None)

    if info:
        user = User.get_by_email(info['email'])

        if user is None:
            user = User.create_account(info['email'], info['name'], None, False, True, group_names=["default"])
        else:
            user.update({
                'name': info['name'],
                'gdpr_consent': True,
            })

        return finish_auth_flow(user)
    else:
        resp = flask.Response("Unauthorized", 401)
        return resp

@api_v1_bp.route('/logout')
@auth_required
def logout():
    if APIKey.get_by_key(flask.g.auth_token):
        return flask.Response("Can't logout an API Key.", 422)

    delete_token(flask.g.auth_user['id'], flask.g.auth_token)
    return flask.jsonify("success")

@api_v1_bp.route('/logout_all')
@auth_required
def logout_all():
    delete_all_temp_tokens_for_user(flask.g.auth_user['id'])
    return flask.jsonify("success")

@api_v1_bp.route('/user')
@requires_some_admin
def get_users_by_filter():
    users = None

    if flask.request.args.get('id'):
        users = User.filter_by_ids([int(x) for x in flask.request.args.get('id').split(',') if x])
    elif flask.request.args.get('email'):
        users = User.search_by_email(flask.request.args.get('email'))
    elif flask.request.args.get('name'):
        users = User.search_by_name(flask.request.args.get('name'))
    elif flask.request.args.get('from') or flask.request.args.get('to'):
        users = User.filter_by_created(flask.request.args.get('from'), flask.request.args.get('to'))
    else:
        users = User.get_normal_accounts()
    return flask.jsonify([user.as_dict() for user in users])

@api_v1_bp.route('/username')
@auth_required
def get_usernames():
    users = []
    if flask.request.args.get('id'):
        users = User.filter_by_ids([int(x) for x in flask.request.args.get('id').split(',') if x])
    return flask.jsonify([{"id": user.id, "name": user.name} for user in users])

@api_v1_bp.route('/user', methods=['POST'])
@requires_some_admin
def create_user_route():
    data = flask.request.json

    required_fields = ['name', 'email']

    for field in required_fields:
        if not (data and field in data):
            return flask.Response("Missing " + field + " .", 400) 

    try:
        user = User.create_account(data['email'], data['name'], None, False, False, group_names=["default"])
        return flask.jsonify(user.as_dict())
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("User with email already exists.", 422)

@api_v1_bp.route('/user/me')
@auth_required
def get_self():
    user = User.get_by_id(flask.g.auth_user['id'])

    if user:
        return flask.jsonify(user.as_dict())
    else:
        return flask.Response("Error finding user", 500)

@api_v1_bp.route('/user/cache')
@auth_required
def get_user_cache():
    return flask.jsonify(flask.g.auth_user)

def dict_response(els):
    return flask.jsonify([el.as_dict() for el in els])

@api_v1_bp.route('/create_token')
@api_v1_bp.route('/user/token', methods=['POST']) # should it be a post if there is no input data?
@auth_required
def create_token():
    key = APIKey.generate(flask.g.auth_user['id'])
    return flask.jsonify(key)

@api_v1_bp.route('/user/token')
@auth_required
def get_user_tokens():
    tokens = APIKey.get_by_user_id(flask.g.auth_user['id'])
    return dict_response(tokens)

@api_v1_bp.route('/user/missing')
@auth_required
def get_user_missing_tos():
    user = User.get_by_id(flask.g.auth_user['id'])

    missing = user.datasets_missing_tos()

    print(missing)

    return flask.jsonify(missing)

@api_v1_bp.route('/user/token/<int:token_id>', methods=['DELETE'])
@auth_required
def delete_token(token_id):
    token = APIKey.get_by_user_id_token_id(flask.g.auth_user['id'], token_id)

    if token:
        token.delete_with_redis()
        return flask.jsonify("success")
    else:
        return flask.Response("Token doesn't exist", 404)


@api_v1_bp.route('/user/<int:user_id>')
@requires_some_admin
def get_user(user_id):
    user = User.user_get_by_id(user_id)

    if user:
        return flask.jsonify(user.as_dict())
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>/debug_redis')
@auth_requires_admin
def user_debug_redis(user_id):
    user = User.get_by_id(user_id)

    if user:
        return flask.jsonify(user.debug_redis())
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>/fix_redis', methods=['POST'])
@auth_requires_admin
def user_fix_redis(user_id):
    user = User.get_by_id(user_id)

    if user:
        soft = flask.request.args.get('soft') == 'true'
        elements_removed, tokens_to_remove = user.debug_redis(soft=soft)
        return flask.jsonify({
            "elements_removed": elements_removed,
            "tokens_to_remove": tokens_to_remove,
        })
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>', methods=['PUT'])
@auth_requires_admin
def modify_user_route(user_id):
    data = flask.request.json

    if data and 'admin' in data and not data['admin'] and flask.g.auth_user['id'] == user_id:
        return flask.Response("Cannot remove admin permissions from yourself.", 403)

    user = User.user_get_by_id(user_id)

    if user:
        user.update(data)
        return flask.jsonify("success")
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>/group')
@requires_some_admin
def get_user_groups(user_id):
    user = User.user_get_by_id(user_id)

    if user:
        groups = user.get_groups()
        return flask.jsonify(groups)
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>/tos')
@requires_some_admin
def get_user_tos(user_id):
    toses = UserTos.get_tos_by_user(user_id)
    return flask.jsonify(toses)

@api_v1_bp.route('/user/<int:user_id>/permissions')
@auth_requires_admin
def get_user_permissions(user_id):
    user = User.user_get_by_id(user_id)

    if user:
        permissions = user.get_permissions()
        return flask.jsonify(permissions)
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/dataset', methods=['GET'])
@auth_required
def get_all_datasets():
    datasets = []

    if flask.g.auth_user['admin']:
        datasets = Dataset.query.order_by(Dataset.id.asc()).all()
    else:
        datasets = DatasetAdmin.get_all_by_admin(flask.g.auth_user['id'])

    return flask.jsonify([dataset.as_dict() for dataset in datasets])

@api_v1_bp.route('/dataset', methods=['POST'])
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

@api_v1_bp.route('/dataset/<int:dataset_id>', methods=['GET'])
@requires_dataset_admin
def get_dataset(dataset_id):
    dataset = Dataset.get_by_id(dataset_id)

    if dataset:
        return flask.jsonify(dataset.as_dict())
    else:
        return flask.Response("Dataset doesn't exist", 404)

@api_v1_bp.route('/dataset/<int:dataset_id>/admin', methods=['GET'])
@requires_dataset_admin
def get_dataset_admins(dataset_id):
    admins = DatasetAdmin.get_all_by_dataset(dataset_id)
    return flask.jsonify(admins)

@api_v1_bp.route('/dataset/<int:dataset_id>/admin', methods=['POST'])
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

@api_v1_bp.route('/dataset/<int:dataset_id>/admin/<int:user_id>', methods=['DELETE'])
@auth_requires_admin
def remove_admin_from_dataset(dataset_id, user_id):
    DatasetAdmin.remove(user_id=user_id, dataset_id=dataset_id)
    return flask.jsonify("success")

@api_v1_bp.route('/dataset/<int:dataset_id>/group', methods=['GET'])
@requires_dataset_admin
def get_all_groups_for_dataset(dataset_id): # nearly identical to get_datasets_from_group_route
    permissions = GroupDatasetPermission.get_all_group_permissions(dataset_id)
    return flask.jsonify(permissions)

@api_v1_bp.route('/dataset/<int:dataset_id>/group', methods=['POST'])
@requires_dataset_admin
def add_dataset_to_group_route(dataset_id):
    data = flask.request.json

    if data and 'group_id' in data:
        permission_ids = [int(x) for x in data.get('permission_ids', [])]
        group_id = int(data['group_id'])

        try:
            GroupDatasetPermission.add(dataset_id=dataset_id, group_id=group_id, permission_ids=permission_ids)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.make_response(flask.jsonify("Dataset already includes group with permission."), 422)
    else:
        return flask.make_response(flask.jsonify("Missing group_id."), 400)

@api_v1_bp.route('/dataset/<int:dataset_id>/group/<int:group_id>/permission/<int:permission_id>', methods=['DELETE'])
@requires_dataset_admin
def remove_dataset_to_group_route(dataset_id, group_id, permission_id):
    GroupDatasetPermission.remove(group_id=group_id, dataset_id=dataset_id, permission_id=permission_id) # TODO return error if group doesn't exist
    return flask.jsonify("success")

@api_v1_bp.route('/group', methods=['GET'])
@auth_required
def get_all_groups():    
    groups = Group.search_by_name(flask.request.args.get('name'))
    return flask.jsonify([group.as_dict() for group in groups])

@api_v1_bp.route('/group', methods=['POST'])
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

@api_v1_bp.route('/group/<int:group_id>', methods=['GET'])
@requires_some_admin
def get_group(group_id):
    group = Group.get_by_id(group_id)

    if group:
        return flask.jsonify(group.as_dict())
    else:
        return flask.Response("Group doesn't exist", 404)

@api_v1_bp.route('/group/<int:group_id>/dataset', methods=['GET'])
@requires_some_admin
def get_datasets_from_group_route(group_id):
    permissions = GroupDatasetPermission.get_permissions_for_group(group_id)
    return flask.jsonify(permissions)

@api_v1_bp.route('/group/<int:group_id>/user', methods=['GET'])
@requires_some_admin
def get_users_for_group_route(group_id):
    # todo, we should check to see if the group is valid before checking for users
    users = UserGroup.get_users(group_id)
    return flask.jsonify(users)

@api_v1_bp.route('/group/<int:group_id>/service_account', methods=['GET'])
@requires_some_admin
def get_sas_for_group_route(group_id):
    # todo, we should check to see if the group is valid before checking for users
    sas = UserGroup.get_service_accounts(group_id)
    return flask.jsonify(sas)

@api_v1_bp.route('/group/<int:group_id>/service_account/<int:sa_id>', methods=['DELETE'])
@requires_group_admin
def remove_sa_from_group_route(group_id, sa_id):
    sag = UserGroup.get(group_id, sa_id)

    if not sag:
        return flask.Response("Service account doesn't belong to group", 404)
    sag.delete()
    return flask.jsonify("success")

@api_v1_bp.route('/group/<int:group_id>/service_account', methods=['POST'])
@requires_group_admin
def add_sa_to_group_route(group_id):
    data = flask.request.json

    if data and 'sa_id' in data:
        try:
            UserGroup.add(data['sa_id'], group_id)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response("Service account already belongs to group.", 422)
    else:
        return flask.Response("Missing sa_id.", 400)


@api_v1_bp.route('/group/<int:group_id>/admin', methods=['GET'])
@requires_some_admin
def get_admins_for_group_route(group_id):
    # todo, we should check to see if the group is valid before checking for users
    users = UserGroup.get_admins(group_id)
    return flask.jsonify(users)

@api_v1_bp.route('/group/<int:group_id>/user', methods=['POST'])
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

@api_v1_bp.route('/group/<int:group_id>/user/<int:user_id>', methods=['PUT'])
@auth_requires_admin
def modify_user_in_group_route(group_id, user_id):
    data = flask.request.json

    usergroup = UserGroup.get(group_id, user_id)

    if usergroup:
        usergroup.update(data)
        return flask.jsonify("success")
    else:
        return flask.Response("User doesn't belong to group", 404)

@api_v1_bp.route('/group/<int:group_id>/user/<int:user_id>', methods=['DELETE'])
@requires_group_admin
def remove_user_from_group_route(group_id, user_id):
    ug = UserGroup.get(group_id, user_id)

    if not ug:
        return flask.Response("User doesn't belong to group", 404)

    if ug.admin and not flask.g.auth_user['admin']:
        return flask.Response("Only superadmins can remove group admins.", 403)

    ug.delete()
    return flask.jsonify("success")

@api_v1_bp.route('/my_permissions')
@auth_required
def get_permissions():
    return flask.jsonify(User.get_by_id(flask.g.auth_user['id']).get_permissions())

@admin_site_bp.route('/')
def send_admin_index():
    return flask.send_from_directory('admin', 'index.html')

@admin_site_bp.route('/<path:path>')
def send_admin_files(path):
    return flask.send_from_directory('admin', path)

@api_v1_bp.route('/service_account')
@requires_some_admin
def get_service_accounts_by_filter():
    service_accounts = None

    if flask.request.args.get('id'):
        service_accounts = User.filter_by_ids([int(x) for x in flask.request.args.get('id').split(',') if x])
    elif flask.request.args.get('name'):
        service_accounts = User.sa_search_by_name(flask.request.args.get('name'))
    else:
        service_accounts = User.get_service_accounts()
    return flask.jsonify([sa.as_dict() for sa in service_accounts])

@api_v1_bp.route('/service_account/<int:sa_id>')
@auth_requires_admin
def get_sa(sa_id):
    sa = User.sa_get_by_id(sa_id)

    if sa and sa.is_service_account:
        return flask.jsonify(sa.as_dict())
    else:
        return flask.Response("Service account doesn't exist", 404)

@api_v1_bp.route('/service_account', methods=['POST'])
@auth_requires_admin
def create_service_account_route():
    data = flask.request.json

    required_fields = ['name']

    for field in required_fields:
        if not (data and field in data):
            return flask.Response("Missing " + field + " .", 400) 

    try:
        sa = User.create_account(data['name'].lower() + '@serviceaccount', data['name'], None, False, False, group_names=["default"], parent_id=flask.g.auth_user['id'])
        return flask.jsonify(sa.as_dict())
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("Service Account with name already exists.", 422)

@api_v1_bp.route('/service_account/<int:sa_id>', methods=['DELETE'])
@auth_requires_admin
def delete_service_account_route(sa_id):
    User.delete_service_account(sa_id)
    return flask.jsonify("success")

@api_v1_bp.route('/service_account/<int:user_id>', methods=['PUT'])
@auth_requires_admin
def modify_service_account_route(user_id):
    data = flask.request.json
    user = User.sa_get_by_id(user_id)

    if user:
        user.update(data)
        return flask.jsonify("success")
    else:
        return flask.Response("Service account doesn't exist", 404)

@api_v1_bp.route('/service_account/<int:sa_id>/group')
@auth_requires_admin
def get_sa_groups(sa_id):
    sa = User.sa_get_by_id(sa_id)

    if sa:
        groups = sa.get_groups()
        return flask.jsonify(groups)
    else:
        return flask.Response("Service account doesn't exist", 404)

@api_v1_bp.route('/service_account/<int:sa_id>/permissions')
@auth_requires_admin
def get_sa_permissions(sa_id):
    sa = User.sa_get_by_id(sa_id)

    if sa:
        permissions = sa.get_permissions()
        return flask.jsonify(permissions)
    else:
        return flask.Response("Service account doesn't exist", 404)

@api_v1_bp.route('/table/<table_id>/has_public')
@auth_required
def temp_table_has_public(table_id):
    return flask.jsonify(CellTemp.table_has_public(table_id))

@api_v1_bp.route('/table/<table_id>/root/<int:root_id>/is_public')
@auth_required
def temp_is_root_public(table_id, root_id):
    return flask.jsonify(CellTemp.is_public(table_id, root_id))

@api_v1_bp.route('/app', methods=['GET'])
@auth_required
def get_apps():
    return flask.jsonify(App.get_all_dict())

@api_v1_bp.route(f'/tos/<int:tos_id>/accept', methods=['GET'])
@auth_required
def tos_accept_view(tos_id):
    existing = UserTos.get(tos_id, flask.g.auth_user['id'])

    if existing:
        return flask.Response(f"You have already accepted the Terms of Service", 200)

    tos = Tos.get_by_id(tos_id)

    if tos:
        return flask.render_template('tos.html', name=tos.name, linkText=tos.linkText)
    else:
        return flask.Response(f"tos doesn't exist", 404)

@api_v1_bp.route(f'/tos/<int:tos_id>/accept', methods=['POST'])
@auth_required
def tos_accept_post(tos_id):
    tos = Tos.get_by_id(tos_id)

    if not tos:
        return flask.Response(f"tos doesn't exist", 404)

    existing = UserTos.get(tos_id, flask.g.auth_user['id'])

    if existing:
        return flask.Response(f"You have already accepted the Terms of Service", 200)

    try:
        UserTos.add(flask.g.auth_user['id'], tos_id)

        redirect = flask.request.args.get('redirect')

        if redirect:
            return flask.redirect(redirect)
        elif flask.request.args.get('postMessage') == 'true':
            delete_token(flask.g.auth_user['id'], flask.g.auth_token)
            user = User.get_by_id(flask.g.auth_user['id'])
            token = user.generate_token(ex=DEFAULT_LOGIN_TOKEN_LENGTH)
            app_urls = [app['url'] for app in App.get_all_dict()]
            return generatePostMessageResponse(token, app_urls)
        else:
            return flask.jsonify("success")
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("Error", 422)

def missing_fields(l, fields):
    return list(set(fields) - set(l.keys()))


def generic_put(bp, name, model, prefix=""):
    # local_bp = flask.Blueprint(f'{name}_bp', __name__, url_prefix=f'/{name}')

    @bp.route(f'{prefix}/<int:model_id>', methods=['PUT'])
    @requires_some_admin
    def modify_route(model_id):
        data = flask.request.json

        print(f"data: {data}")

        el = model.get_by_id(model_id)

        if el:
            el.update(data)
            return flask.jsonify("success")
        else:
            return flask.Response(f"{name} doesn't exist", 404)

    # api_v1_bp.register_blueprint(local_bp)


def create_generic_routes(name, model, required_fields):
    local_bp = flask.Blueprint(f'{name}_bp', __name__, url_prefix=f'/{name}')
    api_v1_bp.register_blueprint(local_bp)

    @local_bp.route('', methods=['GET'])
    @auth_required
    def get_all_route():    
        groups = model.search_by_name(flask.request.args.get('name'))
        return flask.jsonify([group.as_dict() for group in groups])

    @local_bp.route('', methods=['POST'])
    @requires_some_admin
    def create_route():
        data = flask.request.json or {}

        missing = missing_fields(data, required_fields)

        if len(missing):
            return flask.Response(f"Missing fields: {', '.join(missing)}.", 400)

        fields_in_arg_order = [data[x] for x in required_fields]

        try:
            model.add(*fields_in_arg_order)
            return flask.jsonify("success")
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response(f"{name} already exists.", 422)

    @local_bp.route('/<int:model_id>', methods=['GET'])
    @requires_some_admin
    def get_route(model_id):
        el = model.get_by_id(model_id)

        if el:
            return flask.jsonify(el.as_dict())
        else:
            return flask.Response(f"{name} doesn't exist", 404)

    generic_put(local_bp, name, model)

    # @local_bp.route('/<int:model_id>', methods=['PUT'])
    # @requires_some_admin
    # def modify_route(model_id):
    #     data = flask.request.json

    #     el = model.get_by_id(model_id)

    #     if el:
    #         el.update(data)
    #         return flask.jsonify("success")
    #     else:
    #         return flask.Response(f"{name} doesn't exist", 404)



create_generic_routes("tos", Tos, ['name', 'linkText'])

create_generic_routes("permission", Permission, [])

generic_put(api_v1_bp, "dataset", Dataset, prefix="/dataset")#['name', 'tos_id'])
