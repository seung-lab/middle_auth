from functools import wraps
import flask
import json

def auth_required(redis):
    def decorator(f):
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
                cached_user_data = redis.get("token_" + token)

                if cached_user_data:
                    flask.g.user = json.loads(cached_user_data.decode('utf-8'))
                    flask.g.token = token
                    return f(*args, **kwargs)
                else:
                    resp = flask.Response("Invalid/Expired Token", 401)
                    resp.headers['WWW-Authenticate'] = 'Bearer realm="' + AUTH_URI + '", error="invalid_token", error_description="Invalid/Expired Token"'
                    return resp
        return decorated_function
    return decorator

def requires_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if role in flask.g.user['roles']:
                return f(*args, **kwargs)
            else:
                resp = flask.Response("Missing role: {0}".format(role), 401)
                return resp

        return decorated_function
    return decorator
