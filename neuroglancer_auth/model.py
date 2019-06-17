import os
import redis
import json
import secrets

from flask_sqlalchemy import SQLAlchemy, event

db = SQLAlchemy()

r = redis.Redis(
        host=os.environ.get('REDISHOST', 'localhost'),
        port=int(os.environ.get('REDISPORT', 6379)))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    @staticmethod
    def get_by_id(id):
        return User.query.filter_by(id=id).first()
    
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def search_by_email(email):
        return User.query.filter(User.email.like(f'%{email}%')).all()

    def get_roles(self):
        query = db.session.query(Role.name)\
            .join(UserRole, UserRole.role_id == Role.id)\
            .filter(UserRole.user_id == self.id)
        
        roles = query.all()

        return [val for val, in roles]

    def create_cache(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'roles': self.get_roles(),
        }

    def update_cache(self):
        user_json = json.dumps(self.create_cache())

        tokens = r.smembers("userid_" + str(self.id))

        for token_bytes in tokens:
            token = token_bytes.decode('utf-8')
            ttl = r.ttl("token_" + token) # update token without changing ttl

            if ttl == -2: # doesn't exist (expired)
                r.srem("userid_" + str(self.id), token)
            else:
                ttl = ttl if ttl != -1 else None # -1 is no expiration (API KEYS)
                r.set("token_" + token, user_json, nx=False, ex=ttl)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    @staticmethod
    def get_by_id(id):
        return Role.query.filter_by(id=id).first()

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# initial data for roles
def insert_default_roles(target, connection, **kw):
    db.session.add(Role(name="admin"))
    db.session.add(Role(name="edit_all"))
    db.session.commit()

event.listen(Role.__table__, 'after_create', insert_default_roles)

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    role_id = db.Column('role_id', db.Integer, db.ForeignKey("role.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "role_id"),)

    @staticmethod
    def add(user_id, role_id):
        role = UserRole(user_id=user_id, role_id=role_id)
        db.session.add(role)
        db.session.commit()
        user = User.get_by_id(user_id)
        user.update_cache()
    
    @staticmethod
    def remove(user_id, role_id):
        UserRole.query.filter_by(user_id=user_id, role_id=role_id).delete()
        db.session.commit()
        User.get_by_id(user_id).update_cache()

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    key = db.Column(db.String(32), unique=True, nullable=False)

    # load api keys into cache if they don't already exist in redit
    # i.e. new deployment or some redis failure
    @staticmethod
    def load_into_cache():
        api_keys = APIKey().query.all()

        for api_key in api_keys:
            user = User.get_by_id(api_key.user_id)
            r.set("token_" + api_key.key, json.dumps(user.create_cache()), nx=True)
    
    @staticmethod
    def generate(user_id):
        entry = APIKey.query.filter_by(user_id=user_id).first()

        new_entry = not entry

        if new_entry:
            entry = APIKey(user_id=user_id, key="")

        user = User.get_by_id(user_id)
        user_json = json.dumps(user.create_cache())
        token = insert_and_generate_unique_token(user_id, user_json)

        if not new_entry:
            delete_token(user_id, entry.key)

        entry.key = token

        if new_entry:
            db.session.add(entry)

        db.session.commit()

        return token

def insert_and_generate_unique_token(user_id, value, ex=None):
    token = None

    # keep trying to insert a random token into redis until it finds one that is not already in use
    while True:
        token = secrets.token_hex(16)
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

def create_role(role_name):
    role = Role(name=role_name)
    db.session.add(role)
    db.session.commit() # get inserted id
    return role

def create_account(email, name, role_names=[]):
    user = User(username=name, email=email)
    db.session.add(user)
    db.session.flush() # get inserted id

    roles = Role.query.filter(Role.name.in_(role_names)).all()

    for role in roles:
        db.session.add(UserRole(user_id=user.id, role_id=role.id))

    db.session.commit()
    return user
