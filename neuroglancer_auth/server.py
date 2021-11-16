import flask
import google_auth_oauthlib.flow
from oauthlib import oauth2
import googleapiclient.discovery
import urllib
import uuid
import json
from middle_auth_client import auth_required, auth_requires_admin, auth_requires_permission
import sqlalchemy
from yarl import URL

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
from .model.user_custom_name import UserCustomName

import os

from functools import wraps

__version__ = '2.6.0'

TOKEN_NAME = os.environ.get('TOKEN_NAME', "middle_auth_token")
URL_PREFIX = os.environ.get('URL_PREFIX', 'auth')
AUTH_URI = os.environ.get('AUTH_URI', 'localhost:5000/auth') #deprecated
AUTH_URL = os.environ.get('AUTH_URL', AUTH_URI)
STICKY_AUTH_URL = os.environ.get('STICKY_AUTH_URL', AUTH_URL)

DEFAULT_LOGIN_TOKEN_DURATION = 7 * 24 * 60 * 60 # 7 days

version_bp = flask.Blueprint('version_bp', __name__, url_prefix='/' + URL_PREFIX)

@version_bp.route("/version")
def version():
    return "neuroglance_auth -- version " + __version__

api_v1_bp = flask.Blueprint('api_v1_bp', __name__, url_prefix='/' + URL_PREFIX + '/api/v1')
admin_site_bp = flask.Blueprint('admin_site_bp', __name__, url_prefix='/' + URL_PREFIX + '/admin')

CLIENT_SECRETS_FILE = os.environ['AUTH_OAUTH_SECRET']
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

def requires_view_user_data(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        if (flask.g.auth_user['admin']
            or DatasetAdmin.is_dataset_admin_any(flask.g.auth_user['id'])
            or UserGroup.is_group_admin_any(flask.g.auth_user['id'])
            or User.sa_get_by_id(flask.g.auth_user['id'])):
            return f(*args, **kwargs)
        else:
            resp = flask.Response("Requires view user data permissions.", 403)
            return resp

    return decorated_function

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
    flask.session['tos_id'] = flask.request.args.get('tos_id')

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

def redirect_with_args(url, token=None, args={}):
    # query_params = {arg: flask.request.args.get(arg) for arg in args if flask.request.args.get(arg) is not None}   
    resp = flask.redirect(str(URL(url) % args), code=302)
    if token is not None:
        resp.set_cookie(TOKEN_NAME, token, secure=True, httponly=True)
    return resp

def generatePostMessageResponse(token, app_urls):
    return f"""<script type="text/javascript">
        if (window.opener) {{
            window.opener.postMessage({{token: "{token}", app_urls: {app_urls}}}, "*");
        }}
        </script>"""

def finish_auth_flow(token, template_name=None, template_context={}):
    redirect = flask.session.pop('redirect', None)

    if redirect:
        return redirect_with_args(redirect, token, {
            TOKEN_NAME: token, 'middle_auth_url': STICKY_AUTH_URL,
            'token': token # deprecated
        })
    elif template_name is not None:
        return flask.render_template(template_name, **template_context)
    else:
        app_urls = [app['url'] for app in App.get_all_dict()]
        return generatePostMessageResponse(token, app_urls)

def maybe_handle_tos(user, token):
    if flask.session.pop('tos_agree', None): # temp, backwards comp. with flywire.ai
        existing = UserTos.get(user.id, 1)
        if not existing:
            UserTos.add(user.id, 1) # flywire tos
    
    tos_id = flask.session.pop('tos_id', None)

    if tos_id:
        return redirect_with_args(flask.url_for('api_v1_bp.tos_accept_view', tos_id=tos_id), token)
    else:
        return finish_auth_flow(token)

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
    except (oauth2.rfc6749.errors.InvalidGrantError, oauth2.rfc6749.errors.MismatchingStateError) as err:
        print("OAuth Error: {0}".format(err))
        return flask.jsonify("authorization error")

    credentials = flow.credentials

    info = googleapiclient.discovery.build('oauth2', 'v2',
                                          credentials=credentials).userinfo().v2().me().get().execute()

    user = User.get_by_email(info['email'])

    new_account = user is None

    if new_account:
        user = User.create_account(
            info['email'],
            info['name'],
            None, False, False, group_names=["default"])
    else:
        user.update({'google_name': info['name']})
    
    token = user.generate_token(ex=DEFAULT_LOGIN_TOKEN_DURATION)
    
    if new_account:
        return redirect_with_args(flask.url_for('api_v1_bp.register_choose_username_view'), token)
    else:
        return maybe_handle_tos(user, token)

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
@requires_view_user_data
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
    elif flask.request.args.get('page'):
        page = int(flask.request.args.get('page', "1"))
        per_page = int(flask.request.args.get('per_page', "20"))

        page_res = User.get_normal_accounts().paginate(page=page, per_page=per_page)

        return flask.jsonify({
            "pages": page_res.pages,
            "items": [el.as_dict() for el in page_res.items],
        })
    else:
        users = User.get_normal_accounts().all()
    return flask.jsonify([user.as_dict() for user in users])

@api_v1_bp.route('/username')
@auth_required
def get_usernames():
    users = []
    if flask.request.args.get('id'):
        users = User.filter_by_ids([int(x) for x in flask.request.args.get('id').split(',') if x])
    return flask.jsonify([{"id": user.id, "name": user.public_name} for user in users])

@api_v1_bp.route('/user', methods=['POST'])
@requires_some_admin
def create_user_route():
    data = flask.request.json or {}

    required_fields = ['name', 'email']

    missing = missing_fields(data, required_fields)

    if len(missing):
        return flask.Response(f"Missing fields: {', '.join(missing)}.", 400)

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

@api_v1_bp.route('/refresh_token')
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

    return flask.jsonify(missing)

@api_v1_bp.route('/user/token/<int:token_id>', methods=['DELETE'])
@auth_required
def delete_token_endpoint(token_id):
    token = APIKey.get_by_user_id_token_id(flask.g.auth_user['id'], token_id)

    if token:
        token.delete_with_redis()
        return flask.jsonify("success")
    else:
        return flask.Response("Token doesn't exist", 404)


@api_v1_bp.route('/user/<int:user_id>')
@requires_view_user_data
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

@api_v1_bp.route('/user/<int:user_id>/update_cache')
@auth_requires_admin
def user_update_cache(user_id):
    user = User.get_by_id(user_id)

    if user:
        user.update_cache()
        return flask.jsonify("success")
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>/fix_redis', methods=['POST'])
@auth_requires_admin
def user_fix_redis(user_id):
    user = User.get_by_id(user_id)

    if user:
        soft = flask.request.args.get('soft') == 'true'
        elements_removed, tokens_to_remove = user.fix_redis(soft)
        return flask.jsonify({
            "elements_removed": elements_removed,
            "tokens_to_remove": tokens_to_remove,
        })
    else:
        return flask.Response("User doesn't exist", 404)

@api_v1_bp.route('/user/<int:user_id>', methods=['PUT'])
@auth_requires_admin
def modify_user_route(user_id):
    data = flask.request.json or {}

    if 'admin' in data and not data['admin'] and flask.g.auth_user['id'] == user_id:
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
        permissions = user.create_cache()
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

@api_v1_bp.route('/dataset/<int:dataset_id>/admin', methods=['GET'])
@requires_dataset_admin
def get_dataset_admins(dataset_id):
    admins = DatasetAdmin.get_all_by_dataset(dataset_id)
    return flask.jsonify(admins)

@api_v1_bp.route('/dataset/<int:dataset_id>/admin', methods=['POST'])
@requires_dataset_admin
def add_admin_to_dataset(dataset_id):
    data = flask.request.json or {}

    if 'user_id' in data:
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
    data = flask.request.json or {}

    if 'group_id' in data:
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
    data = flask.request.json or {}

    if 'name' in data:
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
    users = UserGroup.get_member_list(group_id)
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
    data = flask.request.json or {}

    if 'sa_id' in data:
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
    data = flask.request.json or {}

    if 'user_id' in data:
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
    return flask.jsonify(User.get_by_id(flask.g.auth_user['id']).create_cache())

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
        service_accounts = User.get_all_service_accounts()
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
    data = flask.request.json or {}

    required_fields = ['name']

    missing = missing_fields(data, required_fields)

    if len(missing):
        return flask.Response(f"Missing fields: {', '.join(missing)}.", 400)

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
    data = flask.request.json or {}
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
        permissions = sa.create_cache()
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

@api_v1_bp.before_request
def api_v1_bp_before_request_debug():
    print("api_v1_bp_before_request_debug")
    print(flask.session)

@api_v1_bp.route(f'/debug', methods=['GET'])
def debug_route():
    return "hi"

@api_v1_bp.route(f'/register/choose_username', methods=['GET'])
@auth_required
def register_choose_username_view():
    user = User.get_by_id(flask.g.auth_user['id'])
    prior_custom = UserCustomName.get(user.id, show_all=True)
    if prior_custom:
        prior_custom = prior_custom.name
    return flask.render_template('username.jinja', user=user, prior=prior_custom)

@api_v1_bp.route(f'/register/choose_username', methods=['POST'])
@auth_required
def register_choose_username_post():
    form = flask.request.form

    user = User.get_by_id(flask.g.auth_user['id'])

    form_custom = form.get('customName')

    if form_custom:
        prior_custom = UserCustomName.get(user.id)
        same_custom = prior_custom and prior_custom.name == form_custom

        if same_custom or UserCustomName.add(user.id, form.get('customName')):
            token = user.generate_token(ex=DEFAULT_LOGIN_TOKEN_DURATION)
            return maybe_handle_tos(user, token)
        else:
            return flask.render_template('username.jinja', user=user, prior=prior_custom.name, failure="You cannot change your custom name.")
            # return flask.Response(f"You cannot change your custom name.", 422) # TODO, do we actually want to limit this?
    else:
        # google name
        UserCustomName.maybe_deactive(user.id)
        return maybe_handle_tos(user, flask.g.auth_token)

@api_v1_bp.route(f'/tos/<int:tos_id>/accept', methods=['GET'])
@auth_required
def tos_accept_view(tos_id):
    tos = Tos.get_by_id(tos_id)

    # temp, flask.session should be avoided because it can conflict with a login flow
    flask.session['redirect'] = flask.request.args.get('redirect')

    if not tos:
        return flask.Response(f"Terms of Service does not exist", 404)
    
    existing = UserTos.get(flask.g.auth_user['id'], tos_id)

    if existing:
        return flask.render_template('tos-msg.html', name=tos.name, msg="You have already accepted the Terms of Service")
    else:
        return flask.render_template('tos-form.html', name=tos.name, text=tos.text)

@api_v1_bp.route(f'/tos/<int:tos_id>/accept', methods=['POST'])
@auth_required
def tos_accept_post(tos_id):
    tos = Tos.get_by_id(tos_id)

    if not tos:
        return flask.Response(f"Terms of Service does not exist", 404)

    user_id = flask.g.auth_user['id']

    existing = UserTos.get(user_id, tos_id)

    if existing:
        return flask.render_template('tos-msg.html', name=tos.name, msg="You have already accepted the Terms of Service")

    try:
        UserTos.add(user_id, tos_id)
        user = User.get_by_id(user_id)
        token = user.generate_token(ex=DEFAULT_LOGIN_TOKEN_DURATION)
        return finish_auth_flow(token, 'tos-msg.html', {"name": tos.name, "msg": "Thank you for accepting the Terms of Service!"})
    except sqlalchemy.exc.IntegrityError as err:
        return flask.Response("Error", 422)

def missing_fields(l, fields):
    return list(set(fields) - set(l.keys()))


def generic_put(bp, name, model, prefix=""):
    @bp.route(f'{prefix}/<int:model_id>', methods=['PUT'])
    @requires_some_admin
    def modify_route(model_id):
        data = flask.request.json or {}

        el = model.get_by_id(model_id)

        if el:
            el.update(data)
            return flask.jsonify("success")
        else:
            return flask.Response(f"{name} doesn't exist", 404)

def generic_post(bp, name, model, prefix="", required_fields=[]):
    @bp.route(f'{prefix}', methods=['POST'])
    @requires_some_admin
    def create_route():
        data = flask.request.json or {}

        missing = missing_fields(data, required_fields)

        if len(missing):
            return flask.Response(f"Missing fields: {', '.join(missing)}.", 400)

        fields_in_arg_order = [data[x] for x in required_fields]

        for field in required_fields:
            if data[field] == "":
                return flask.Response(f"{field} cannot be blank.", 400)

        try:
            el = model.add(*fields_in_arg_order)
            return flask.jsonify(el.as_dict())
        except sqlalchemy.exc.IntegrityError as err:
            return flask.Response(f"{name} already exists.", 422)

def generic_get_specific(bp, name, model, prefix=""):
    @bp.route(f'{prefix}/<int:model_id>', methods=['GET'])
    @requires_some_admin
    def get_route(model_id):
        el = model.get_by_id(model_id)

        if el:
            return flask.jsonify(el.as_dict())
        else:
            return flask.Response(f"{name} doesn't exist", 404)


def create_generic_routes(name, model, required_fields):
    local_bp = flask.Blueprint(f'{name}_bp', __name__, url_prefix=f'/{name}')
    api_v1_bp.register_blueprint(local_bp)

    @local_bp.route('', methods=['GET'])
    @auth_required
    def get_all_route():    
        els = model.search_by_name(flask.request.args.get('name'))
        return dict_response(els)

    generic_get_specific(local_bp, name, model)
    generic_post(local_bp, name, model, prefix="", required_fields=required_fields)
    generic_put(local_bp, name, model)

create_generic_routes("tos", Tos, ['name', 'text'])

create_generic_routes("permission", Permission, ['name'])

generic_put(api_v1_bp, "dataset", Dataset, prefix="/dataset")#['name', 'tos_id'])
generic_post(api_v1_bp, "dataset", Dataset, prefix="/dataset", required_fields=['name', 'tos_id'])
generic_get_specific(api_v1_bp, "dataset", Dataset, prefix="/dataset")

@api_v1_bp.route('/user/<int:user_id>', methods=['DELETE'])
@auth_requires_admin
def delete_account_route(user_id):
    if user_id == flask.g.auth_user['id']:
        return flask.Response("Cannot delete yourself.", 403)

    User.delete_user_account(user_id)
    return flask.jsonify("success")
