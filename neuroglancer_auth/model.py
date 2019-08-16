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
    name = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    admin = db.Column('admin', db.Boolean, default=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "admin": self.admin,
        }
    
    @staticmethod
    def create_account(email, name, admin=False, group_names=[]):
        user = User(name=name, email=email, admin=admin)
        db.session.add(user)
        db.session.flush() # get inserted id

        groups = Group.query.filter(Group.name.in_(group_names)).all()

        for group in groups:
            db.session.add(UserGroup(user_id=user.id, group_id=group.id))

        db.session.commit()
        return user

    @staticmethod
    def get_by_id(id):
        return User.query.filter_by(id=id).first()
    
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def search_by_email(email):
        if email:
            return User.query.filter(User.email.ilike(f'%{email}%')).all()
        else:
            return User.query.limit(20)
    
    def update(self, data):
        if 'admin' in data:
            self.admin = data['admin']
        
        if 'name' in data:
            self.name = data['name']

        db.session.commit()
        self.update_cache()

    def get_groups(self):
        query = db.session.query(Group.id, Group.name)\
            .join(UserGroup, UserGroup.group_id == Group.id)\
            .filter(UserGroup.user_id == self.id)
        
        groups = query.all()

        return [{'id': id, 'name': name} for id, name in groups]

    def get_permissions(self):
        query = db.session.query(GroupDataset.dataset_id, Dataset.name, GroupDataset.level)\
            .join(UserGroup, UserGroup.group_id == GroupDataset.group_id)\
            .join(Dataset, Dataset.id == GroupDataset.dataset_id)\
            .filter(UserGroup.user_id == self.id)
        
        permissions = query.all()
        
        return [{'id': dataset_id, 'name': dataset_name, 'level': level} for dataset_id, dataset_name, level in permissions]

    def create_cache(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'admin': self.admin,
            'groups': self.get_groups(),
            'permissions': {x['name']: x['level'] for x in self.get_permissions()},
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

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
        }

    @staticmethod
    def get_by_id(id):
        return Group.query.filter_by(id=id).first()

    @staticmethod
    def search_by_name(name):
        if name:
            return Group.query.filter(Group.name.ilike(f'%{name}%')).all()
        else:
            return Group.query.limit(20)

    @staticmethod
    def add(name):
        group = Group(name=name)
        db.session.add(group)
        db.session.commit()
        return group
    
    def get_permissions(self):
        query = db.session.query(GroupDataset.dataset_id, Dataset.name, GroupDataset.level)\
            .join(Dataset, Dataset.id == GroupDataset.dataset_id)\
            .filter(GroupDataset.group_id == self.id)
        
        permissions = query.all()

        return [{'id': dataset_id, 'name': dataset_name, 'level': level} for dataset_id, dataset_name, level in permissions]

    def get_users(self):
        users = db.session.query(UserGroup.user_id, User.name)\
            .filter(UserGroup.user_id == User.id)\
            .filter(UserGroup.group_id == self.id).all()

        return [{"id": id, "name": name} for (id, name) in users]

    def update_cache(self):
        users = self.get_users()

        for user in users:
            User.get_by_id(user["id"]).update_cache()

class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column('group_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "group_id"),)

    @staticmethod
    def add(user_id, group_id):
        ug = UserGroup(user_id=user_id, group_id=group_id)
        db.session.add(ug)
        db.session.commit()
        user = User.get_by_id(user_id)
        user.update_cache()
    
    @staticmethod
    def remove(user_id, group_id):
        UserGroup.query.filter_by(user_id=user_id, group_id=group_id).delete()
        db.session.commit()
        user = User.get_by_id(user_id).update_cache()

def insert_default_groups(target, connection, **kw):
    db.session.add(Group(name="default"))
    db.session.commit()

event.listen(Group.__table__, 'after_create', insert_default_groups)

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
        }

    @staticmethod
    def get_by_id(id):
        return Dataset.query.filter_by(id=id).first()

    @staticmethod
    def search_by_name(name):
        if name:
            return Dataset.query.filter(Dataset.name.ilike(f'%{name}%')).all()
        else:
            return Dataset.query.limit(20)

    @staticmethod
    def add(name):
        dataset = Dataset(name=name)
        db.session.add(dataset)
        db.session.commit()
        return dataset

class GroupDataset(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    group_id = db.Column('group_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    dataset_id = db.Column('dataset_id', db.Integer, db.ForeignKey("dataset.id"), nullable=False)
    level = db.Column('level', db.Integer, nullable=False, default=0)
    __table_args__ = (db.UniqueConstraint("group_id", "dataset_id"),)

    @staticmethod
    def add(group_id, dataset_id, level):
        gd = GroupDataset(group_id=group_id, dataset_id=dataset_id, level=level)
        db.session.add(gd)
        db.session.commit()
        group = Group.get_by_id(group_id)
        group.update_cache()
    
    @staticmethod
    def remove(group_id, dataset_id):
        GroupDataset.query.filter_by(group_id=group_id, dataset_id=dataset_id).delete()
        db.session.commit()
        group = Group.get_by_id(group_id).update_cache()
    
    def update(self, level):
        self.level = level
        db.session.commit()
        group = Group.get_by_id(self.group_id)
        group.update_cache()

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    key = db.Column(db.String(32), unique=True, nullable=False)

    # load api keys into cache if they don't already exist in redis
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
