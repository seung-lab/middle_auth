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
        return User.query.filter(User.email.like(f'%{email}%')).all()

    def get_groups(self):
        query = db.session.query(Group.name)\
            .join(UserGroup, UserGroup.group_id == Group.id)\
            .filter(UserGroup.user_id == self.id)
        
        groups = query.all()

        return [name for name, in groups]

    def get_permissions(self):
        query = db.session.query(GroupDataset.dataset_name, GroupDataset.can_view, GroupDataset.can_edit, GroupDataset.can_admin)\
            .join(UserGroup, UserGroup.group_id == GroupDataset.group_id)\
            .filter(UserGroup.user_id == self.id)
        
        permissions = query.all()

        permissions_combined = {}

        for (dataset_name, can_view, can_edit, can_admin) in permissions:
            current = permissions_combined.get(dataset_name, 0)

            current |= (1<<0) * can_view
            current |= (1<<1) * can_edit
            current |= (1<<2) * can_admin

            permissions_combined[dataset_name] = current
        
        return permissions_combined

    def create_cache(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'admin': self.admin,
            'groups': self.get_groups(),
            'permissions': self.get_permissions(),
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
    def add(name):
        group = Group(name=name)
        db.session.add(group)
        db.session.commit()
        return group
    
    def get_permissions(self):
        query = db.session.query(GroupDataset.dataset_name, GroupDataset.can_view, GroupDataset.can_edit, GroupDataset.can_admin)\
            .filter(GroupDataset.group_id == self.id)
        
        permissions = query.all()

        permissions_combined = {}

        for (dataset_name, can_view, can_edit, can_admin) in permissions:
            current = permissions_combined.get(dataset_name, 0)

            current |= (1<<0) * can_view
            current |= (1<<1) * can_edit
            current |= (1<<2) * can_admin

            permissions_combined[dataset_name] = current
        
        return permissions_combined.items()

    def get_users(self):
        users = db.session.query(UserGroup.user_id, User.name)\
            .filter(UserGroup.user_id == User.id)\
            .filter(UserGroup.group_id == self.id).all()

        return [{"id": id, "name": name} for (id,name) in users]

    def update_cache(self):
        users = self.get_users()

        for user_id in users:
            User.get_by_id(user_id).update_cache()

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

class GroupDataset(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    group_id = db.Column('group_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    dataset_name = db.Column('dataset_name', db.String(32), nullable=True, index=True) # nullable because the dataset may be deleted and we want to represent that without deleting the row
    __table_args__ = (db.UniqueConstraint("group_id", "dataset_name"),)

    can_view = db.Column('can_view', db.Boolean, server_default='f', nullable=False)
    can_edit = db.Column('can_edit', db.Boolean, server_default='f', nullable=False)
    can_admin = db.Column('can_admin', db.Boolean, server_default='f', nullable=False)

    @staticmethod
    def add(group_id, dataset_name, can_view, can_edit, can_admin):
        gd = GroupDataset(group_id=group_id, dataset_name=dataset_name, can_view=can_view, can_edit=can_edit, can_admin=can_admin)
        db.session.add(gd)
        db.session.commit()
        group = Group.get_by_id(group_id)
        group.update_cache()
    
    @staticmethod
    def remove(group_id, dataset_name):
        GroupDataset.query.filter_by(group_id=group_id, dataset_name=dataset_name).delete()
        db.session.commit()
        group = Group.get_by_id(group_id).update_cache()
    
    @staticmethod
    def get_all_datasets():
        datasets = db.session.query(GroupDataset.dataset_name).all()
        return [dataset_name for dataset_name, in datasets]
    
    def update(can_view, can_edit, can_admin):
        self.can_view = can_view
        self.can_edit = can_edit
        self.can_admin = can_admin
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
