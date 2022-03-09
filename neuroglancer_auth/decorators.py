from functools import wraps
import flask
import json
import os
from urllib.parse import quote

from furl import furl
import cachetools.func
from cachetools import cached, TTLCache
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from .ratelimit import RateLimitError, rate_limit

AUTH_URI = os.environ.get('AUTH_URI', 'localhost:5000/auth')
AUTH_URL = os.environ.get('AUTH_URL', AUTH_URI)
INFO_URL = os.environ.get('INFO_URL', 'localhost:5000/info')
STICKY_AUTH_URL = os.environ.get('STICKY_AUTH_URL', AUTH_URL)

USE_REDIS = os.environ.get('AUTH_USE_REDIS', "false") == "true"
TOKEN_NAME = os.environ.get('TOKEN_NAME', "middle_auth_token")
CACHE_MAXSIZE = int(os.environ.get('TOKEN_CACHE_MAXSIZE', "1024"))
CACHE_TTL = int(os.environ.get('TOKEN_CACHE_TTL', "300"))

SKIP_CACHE_LIMIT = int(os.environ.get('TOKEN_CACHE_SKIP_LIMIT', "20"))
SKIP_CACHE_WINDOW_SEC = int(os.environ.get(
    'TOKEN_CACHE_SKIP_WINDOW_SEC', "300"))

AUTH_DISABLED = os.environ.get('AUTH_DISABLED', "false") == "true"


retries = Retry(total=5,
                backoff_factor=0.1,
                status_forcelist=[ 500, 502, 503, 504 ])

session = requests.Session()
session.mount('https://' + AUTH_URI, HTTPAdapter(max_retries=retries))
session.mount('https://' + INFO_URL, HTTPAdapter(max_retries=retries))


r = None
if USE_REDIS:
    import redis
    r = redis.Redis(
        host=os.environ.get('REDISHOST', 'localhost'),
        port=int(os.environ.get('REDISPORT', 6379)))


class AuthorizationError(Exception):
    pass


def get_usernames(user_ids, token=None):
    if AUTH_DISABLED:
        return []

    if token is None:
        raise ValueError('missing token')
    if len(user_ids):
        users_request = session.get(f"https://{AUTH_URL}/api/v1/username?id={','.join(map(str, user_ids))}",
                                     headers={
                                         'authorization': 'Bearer ' + token},
                                     timeout=5)

        if users_request.status_code in [401, 403]:
            raise AuthorizationError(users_request.text)
        elif users_request.status_code == 200:
            id_to_name = {x['id']: x['name'] for x in users_request.json()}
            return [id_to_name[x] for x in user_ids]
        else:
            raise RuntimeError('get_usernames request failed')
    else:
        return []

token_to_user_cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)

user_id_to_user_cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)

@cached(cache=token_to_user_cache)
def user_cache_http(token):
    user_request = session.get(
        f"https://{AUTH_URL}/api/v1/user/cache", headers={'authorization': 'Bearer ' + token})
    if user_request.status_code == 200:
        return user_request.json()

@cached(cache=user_id_to_user_cache)
def user_id_to_user_cache_http(user_id, service_token=None):
    token = (
        service_token
        if service_token
        else flask.current_app.config.get("AUTH_TOKEN", "")
    )
    user_request = session.get(
        f"https://{AUTH_URL}/api/v1/user/{user_id}/permissions", headers={'authorization': 'Bearer ' + token})
    if user_request.status_code == 200:
        return user_request.json()

@rate_limit(limit_args=[0], limit=SKIP_CACHE_LIMIT, window_sec=SKIP_CACHE_WINDOW_SEC)
def clear_user_cache_maybe(token):
    token_to_user_cache.pop((token,), None)


def get_user_cache(token):
    if USE_REDIS:
        cached_user_data = r.get("token_" + token)
        if cached_user_data:
            return json.loads(cached_user_data.decode('utf-8'))
    else:
        return user_cache_http(token)


@cachetools.func.ttl_cache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
def is_root_public(table_id, root_id, token):
    if root_id is None:
        return False

    if AUTH_DISABLED:
        return True

    url = f"https://{AUTH_URL}/api/v1/table/{table_id}/root/{root_id}/is_public"

    req = session.get(
        url, headers={'authorization': 'Bearer ' + token}, timeout=5)

    if req.status_code == 200:
        return req.json()
    else:
        raise RuntimeError('is_root_public request failed')


@cachetools.func.ttl_cache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
def table_has_public(table_id, token):
    if AUTH_DISABLED:
        return True

    url = f"https://{AUTH_URL}/api/v1/table/{table_id}/has_public"

    req = session.get(
        url, headers={'authorization': 'Bearer ' + token}, timeout=5)
    if req.status_code == 200:
        return req.json()
    else:
        raise RuntimeError('has_public request failed')


@cachetools.func.ttl_cache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
def dataset_from_table_id(service_namespace, table_id, token):
    url = f"https://{INFO_URL}/api/v2/tablemapping/service/{service_namespace}/table/{table_id}/permission_group"
    req = session.get(
        url, headers={'authorization': 'Bearer ' + token}, timeout=5)
    if req.status_code == 200:
        return req.json()
    else:
        raise RuntimeError(
            f'failed to lookup dataset for service {service_namespace} & table_id: {table_id}: status code {req.status_code}. content: {req.content}')


def user_has_permission(permission, table_id, resource_namespace, service_token=None):
    if AUTH_DISABLED:
        return True

    token = (
        service_token
        if service_token
        else flask.current_app.config.get("AUTH_TOKEN", "")
    )

    dataset = dataset_from_table_id(resource_namespace, table_id, token)

    has_permission = permission in flask.g.auth_user.get("permissions_v2", {}).get(
        dataset, []
    )
    return has_permission


def is_programmatic_access():
    auth_header = flask.request.headers.get('authorization')
    xrw_header = flask.request.headers.get('X-Requested-With')

    return xrw_header or auth_header or flask.request.environ.get(
        'HTTP_ORIGIN')


def auth_required(func=None, *, required_permission=None, public_table_key=None, public_node_key=None, service_token=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if flask.request.method == 'OPTIONS':
                return f(*args, **kwargs)

            if hasattr(flask.g, 'auth_token'):
                # if authorization header has already been parsed, don't need to re-parse
                # this allows auth_required to be an optional decorator if auth_requires_role is also used
                return f(*args, **kwargs)

            flask.g.public_access_cache = None

            def lazy_check_public_access():
                if flask.g.public_access_cache is None:
                    if service_token and required_permission != 'edit':
                        if public_node_key is not None:
                            flask.g.public_access_cache = is_root_public(kwargs.get(
                                public_table_key), kwargs.get(public_node_key), service_token)
                        elif public_table_key is not None:
                            flask.g.public_access_cache = table_has_public(
                                kwargs.get(public_table_key), service_token)
                        else:
                            flask.g.public_access_cache = False
                    else:
                        flask.g.public_access_cache = False

                return flask.g.public_access_cache

            flask.g.public_access = lazy_check_public_access

            if AUTH_DISABLED:
                flask.g.auth_user = {'id': 0, 'service_account': False, 'name': 'AUTH_DISABLED',
                                     'email': 'AUTH_DISABLED@AUTH.DISABLED', 'admin': True, 'groups': [], 'permissions': {}}
                flask.g.auth_token = 'AUTH_DISABLED'
                return f(*args, **kwargs)

            cookie_name = TOKEN_NAME
            token = flask.request.cookies.get(cookie_name)

            auth_header = flask.request.headers.get('authorization')

            programmatic_access = is_programmatic_access()

            AUTHORIZE_URI = 'https://' + STICKY_AUTH_URL + '/api/v1/authorize'

            query_param_token = flask.request.args.get(TOKEN_NAME)

            if query_param_token:
                token = query_param_token

            auth_header = flask.request.headers.get('authorization')

            if auth_header:
                if not auth_header.startswith('Bearer '):
                    resp = make_api_error(400, "bad_auth_header", "Authorization header must begin with \'Bearer\'")
                    resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTHORIZE_URI + \
                        '", error="invalid_request", error_description="Header must begin with \'Bearer\'"'
                    return resp
                else:  # auth header takes priority
                    token = auth_header.split(' ')[1]  # remove schema

            if programmatic_access:
                if not token and not flask.g.public_access():
                    resp = make_api_error(401, "no_token", "Unauthorized - No Token Provided")
                    resp.headers['WWW-Authenticate'] = 'Bearer realm="' + \
                        AUTHORIZE_URI + '"'
                    return resp
            # direct browser access, or a non-browser request missing auth header (user error) TODO: check user agent to deliver 401 in this case
            else:
                if query_param_token:
                    resp = flask.make_response(flask.redirect(
                        furl(flask.request.url).remove([TOKEN_NAME, 'token']).url, code=302))
                    resp.set_cookie(cookie_name, query_param_token,
                                    secure=True, httponly=True)
                    return resp

            cached_user_data = get_user_cache(token) if token else None

            if cached_user_data:
                flask.g.auth_user = cached_user_data
                flask.g.auth_token = token
                return f(*args, **kwargs)
            elif not programmatic_access and not flask.g.public_access():
                return flask.redirect(AUTHORIZE_URI + '?redirect=' + quote(flask.request.url), code=302)
            elif not flask.g.public_access():
                resp = make_api_error(401, "invalid_token", "Unauthorized - Token is Invalid or Expired")
                resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTHORIZE_URI + \
                    '", error="invalid_token", error_description="Invalid/Expired Token"'
                return resp
            else:
                flask.g.auth_user = {'id': 0, 'service_account': False, 'name': '',
                                     'email': '', 'admin': False, 'groups': [], 'permissions': {}}
                flask.g.auth_token = None
                return f(*args, **kwargs)

        return decorated_function

    if func:
        return decorator(func)
    else:
        return decorator


def auth_requires_admin(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        if flask.request.method == 'OPTIONS':
            return f(*args, **kwargs)

        if not flask.g.auth_user['admin']:
            resp = flask.Response("Requires superadmin privilege.", 403)
            return resp
        else:
            return f(*args, **kwargs)

    return decorated_function

def users_share_common_group(user_id, excluded_groups=None, service_token=None):
    excluded_groups = (
        excluded_groups
        if excluded_groups
        else flask.current_app.config.get("AUTH_SHARED_EXCLUDED_GROUPS", [])
    )

    if AUTH_DISABLED:
        return True

    target_user_data = user_id_to_user_cache_http(user_id, service_token)

    if target_user_data:
        request_user_groups = flask.g.auth_user['groups']
        target_user_groups = target_user_data['groups']

        shared_groups = [g for g in request_user_groups if g in target_user_groups and g not in excluded_groups]

        print(f"shared_groups: {shared_groups}")

        if len(shared_groups) == 0:
            return False
        else:
            return True
    else:
        print(f"target_user_data lookup failed: {target_user_data}")
        raise RuntimeError('user_data lookup request failed')

def make_api_error(http_status, api_code, msg=None, data=None):
    res = {"error": api_code}

    if msg is not None:
        res["message"] = msg

    if data is not None:
        res["data"] = data

    response = flask.jsonify(res)
    response.status_code = http_status
    return response


def auth_requires_permission(required_permission, public_table_key=None,
                             public_node_key=None, service_token=None,
                             dataset=None, table_arg='table_id', table_id=None, resource_namespace=None):
    def decorator(f):
        @wraps(f)
        @auth_required(required_permission=required_permission,
                       public_table_key=public_table_key,
                       public_node_key=public_node_key, service_token=service_token)
        def decorated_function(*args, **kwargs):
            if flask.request.method == 'OPTIONS':
                return f(*args, **kwargs)

            local_table_id = table_id
            if local_table_id is None:
                local_table_id = kwargs.get(table_arg)

            if local_table_id is None and dataset is None:
                return make_api_error(400,
                                      "missing_table_id",
                                      msg = "Missing table_id")

            local_dataset = dataset
            local_resource_namespace = resource_namespace
            if local_dataset is None:
                if local_resource_namespace is None:
                    local_resource_namespace = flask.current_app.config.get(
                        'AUTH_SERVICE_NAMESPACE', 'datastack')
                service_token_local = service_token if service_token else flask.current_app.config.get(
                    'AUTH_TOKEN', "")
                try:
                    local_dataset = dataset_from_table_id(
                        local_resource_namespace, local_table_id, service_token_local)
                except RuntimeError:
                    return make_api_error(400,
                        "invalid_table_id",
                        msg = "Invalid table_id for service",
                        data = {'table_id': local_table_id,
                                'resource_namespace': local_resource_namespace,
                                'auth_dataset':local_dataset})

            def has_permission(auth_user):
                res = required_permission in auth_user.get(
                    'permissions_v2', {}).get(local_dataset, [])

                if not 'permissions_v2' in auth_user:  # backwards compatability
                    required_level = ['none', 'view', 'edit'].index(
                        required_permission)
                    level_for_dataset = auth_user.get(
                        'permissions', {}).get(local_dataset, 0)
                    res = level_for_dataset >= required_level

                return res

            # public_access won't be true for edit requests
            if AUTH_DISABLED or has_permission(flask.g.auth_user) or flask.g.public_access():
                return f(*args, **kwargs)
            else:
                if flask.g.auth_token:  # should always exist
                    try:
                        clear_user_cache_maybe(flask.g.auth_token)
                        # try again
                        cached_user_data = get_user_cache(flask.g.auth_token)
                        if cached_user_data:
                            flask.g.auth_user = cached_user_data
                            if has_permission(flask.g.auth_user):
                                # cached permissions were out of date
                                return f(*args, **kwargs)
                    except RateLimitError:
                        pass

                missing_tos = flask.g.auth_user.get('missing_tos', [])
                relevant_tos = [
                    tos for tos in missing_tos if tos['dataset_name'] == local_dataset]

                if len(relevant_tos):
                    tos_form_url = f"https://{STICKY_AUTH_URL}/api/v1/tos/{relevant_tos[0]['tos_id']}/accept"

                    if is_programmatic_access():
                        return make_api_error(403, "missing_tos",
                                              msg="Need to accept Terms of Service to access resource.", data={
                                                  "tos_id": relevant_tos[0]['tos_id'],
                                                  "tos_name": relevant_tos[0]['tos_name'],
                                                  "tos_form_url": tos_form_url,
                                              })
                    else:
                        return flask.redirect(tos_form_url + '?redirect=' + quote(flask.request.url), code=302)
                message = "Missing permission: {0} for dataset {1}".format(
                    required_permission, local_dataset)
                resp = make_api_error(403,
                                      "missing_permission",
                                      msg = message,
                                      data = {'required_permission': required_permission,
                                      'auth_dataset': local_dataset})
                
                return resp

        return decorated_function
    return decorator


def auth_requires_group(required_group):
    def decorator(f):
        @wraps(f)
        @auth_required
        def decorated_function(*args, **kwargs):
            if flask.request.method == 'OPTIONS':
                return f(*args, **kwargs)

            if not AUTH_DISABLED and required_group not in flask.g.auth_user['groups']:
                clear_user_cache_maybe(flask.g.auth_token)
                resp = flask.Response(
                    "Requires membership of group: {0}".format(required_group), 403)
                return resp

            return f(*args, **kwargs)

        return decorated_function
    return decorator
