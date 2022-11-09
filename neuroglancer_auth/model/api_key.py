from .base import db, r

import json
import secrets
from sqlalchemy.sql import func

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String(120), unique=False, nullable=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), unique=False, nullable=False)
    key = db.Column(db.String(32), unique=True, nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    last_used = db.Column(db.DateTime, nullable=True)

    def as_dict(self):
        res = {
            "id": self.id,
            "user_id": self.user_id,
            "token": self.key,
            "description": self.description,
            "created": self.created,
            "updated": self.updated,
            "last_used": self.last_used,
        }

        return res

    @staticmethod
    def get_by_key(key):
        return APIKey.query.filter_by(key=key).first()
    
    def update_last_used(self):
        self.last_used = func.now()
        db.session.commit()
    
    @staticmethod
    def get_by_user_id(user_id):
        return APIKey.query.filter_by(user_id=user_id).order_by(APIKey.id.desc()).all()

    @staticmethod
    def get_by_user_id_token_id(user_id, token_id):
        return APIKey.query.filter_by(user_id=user_id, id=token_id).first()

    # load api keys into cache if they don't already exist in redis
    # i.e. new deployment or some redis failure
    @staticmethod
    def load_into_cache():
        from .user import User
        api_keys = APIKey().query.all()

        for api_key in api_keys:
            if not r.get("token_" + api_key.key):
                user = User.get_by_id(api_key.user_id)
                print(f"load_into_cache: {user.id} {api_key.user_id} {api_key.key}")
                maybe_insert_token(user.id, api_key.key, json.dumps(user.create_cache()), ex=None)

    @staticmethod
    def generate(user_id, description=None):
        from .user import User
        user = User.get_by_id(user_id)

        print(f"baaa")

        print(f"user_id: {user_id}")

        token = user.generate_token()

        entry = APIKey(user_id=user_id, key=token, description=description)
        db.session.add(entry)
        db.session.commit()

        return token

    @staticmethod
    def refresh(user_id): #deprecated
        from .user import User
        user = User.get_by_id(user_id)

        entry = APIKey.query.filter_by(user_id=user_id).first()

        new_entry = not entry

        if new_entry:
            entry = APIKey(user_id=user_id, key="")

        token = user.generate_token()

        if not new_entry:
            delete_token(user_id, entry.key)

        entry.key = token

        entry = APIKey(user_id=user_id, key=token)

        if new_entry:
            db.session.add(entry)

        db.session.commit()

        return token

    def delete_with_redis(self):
        delete_token(self.user_id, self.key)
        db.session.delete(self)
        db.session.commit()

def maybe_insert_token(user_id, token, value, ex=None):
    # nx = Only set the key if it does not already exist
    not_dupe = r.set("token_" + token, value, nx=True, ex=ex)

    if not_dupe:
        r.sadd(tokens_key(user_id), token)

    return not_dupe

def delete_token(user_id, token):
    p = r.pipeline()
    p.delete("token_" + token)
    p.srem(tokens_key(user_id), token)
    p.execute()

def tokens_key(user_id):
    return "userid_" + str(user_id)

def delete_all_tokens_for_user(user_id):
    tokens = r.smembers(tokens_key(user_id))

    for token_bytes in tokens:
        token = token_bytes.decode('utf-8')
        delete_token(user_id, token)

def delete_all_temp_tokens_for_user(user_id):
    tokens = r.smembers(tokens_key(user_id))

    for token_bytes in tokens:
        token = token_bytes.decode('utf-8')
        ttl = r.ttl("token_" + token)
        if ttl != -1: # don't delete API keys
            delete_token(user_id, token)

def insert_and_generate_unique_token(user_id, value, ex=None):
    # keep trying to insert a random token into redis until it finds one that is not already in use
    while True:
        token = secrets.token_hex(16)
        if maybe_insert_token(user_id, token, value, ex):
            return token

def get_redis_cache(token):
    cached_user_data = r.get("token_" + token)
    if cached_user_data:
        return json.loads(cached_user_data.decode('utf-8'))

def get_user_id_from_token(token):
    redis_res = r.get("token_" + token)

    if redis_res:
        redis_res = json.loads(redis_res.decode('utf-8'))
        return redis_res['id']
    else:
        api_key = APIKey.get_by_key(token)
        if api_key:
            return api_key.user_id
