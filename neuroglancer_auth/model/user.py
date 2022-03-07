from os import name
from .base import db, r
from .api_key import insert_and_generate_unique_token, APIKey, tokens_key, delete_all_tokens_for_user

import json
from sqlalchemy.sql import func
import sqlalchemy

from sqlalchemy.orm import relationship

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=False, nullable=False) # public
    email = db.Column(db.String(120), unique=True, nullable=False) # public + affiliation
    admin = db.Column(db.Boolean, server_default="0", nullable=False)
    gdpr_consent = db.Column(db.Boolean, server_default="0", nullable=False)
    pi = db.Column(db.String(80), server_default="", nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    parent_id = db.Column('parent_id', db.Integer, db.ForeignKey("user.id"), nullable=True)
    read_only = db.Column(db.Boolean, server_default="0", nullable=False)

    def __repr__(self):
        return self.name

    groups = relationship("Group", secondary='user_group', backref=db.backref('users', lazy='dynamic'))
    associations = relationship("Association", secondary='user_association', backref=db.backref('users', lazy='dynamic'))

    def as_dict(self):
        res = {
            "id": self.id,
            "service_account": self.is_service_account,
            "parent_id": self.parent_id,
            "read_only": self.read_only,
            "name": self.public_name,
            "email": self.email,
            "admin": self.admin,
            "created": self.created,
            "pi": self.pi,
            "gdpr_consent": self.gdpr_consent,
            "admin_datasets": self.get_datasets_adminning()
        }

        if self.is_service_account:
            parent = self.parent
            res["token"] = self.get_service_account_token()
            res["parent"] = parent.as_dict()

        return res

    @property
    def public_name(self):
        from .user_custom_name import UserCustomName
        custom_name = UserCustomName.get(self.id)
        return custom_name.name if custom_name else self.name

    def debug_redis(self):
        tokens = r.smembers(self.tokens_key)
        tokens = [token_bytes.decode('utf-8') for token_bytes in tokens]

        res = {
            "tokens": tokens,
            "values": {}
        }

        for token in tokens:
            cached_user_data = r.get("token_" + token)
            ttl = r.ttl("token_" + token)
            if cached_user_data:
                res["values"][token] = {
                    "data": json.loads(cached_user_data.decode('utf-8')),
                    "ttl": ttl
                }

            # check for an api key
            apikey = APIKey.get_by_key(token)

            if apikey:
                res["values"][token] = res["values"][token] or {}
                res["values"][token]["apikey"] = {"user_id": apikey.user_id}

        return res

    def fix_redis(self, soft=False):
        tokens = r.smembers(self.tokens_key)
        tokens = [token_bytes.decode('utf-8') for token_bytes in tokens]

        tokens_to_remove = []
        users_to_update = [self.id]

        for token in tokens:
            apikey = APIKey.get_by_key(token)

            if apikey and apikey.user_id != self.id:
                tokens_to_remove += [token]
                users_to_update += [apikey.user_id]

        elements_removed = 0

        if not soft:
            elements_removed = r.srem(self.tokens_key, *tokens_to_remove)

            for user_id in users_to_update:
                user = User.get_by_id(user_id)
                user.update_cache()


        return elements_removed, tokens_to_remove

    @property
    def is_service_account(self):
        return self.parent_id is not None
    
    @property
    def parent(self):
        if self.parent_id:
            return User.user_get_by_id(self.parent_id)
    
    @property
    def tokens_key(self):
        return tokens_key(self.id)

    @staticmethod
    def create_account(email, name, pi, admin=False, gdpr_consent=False, group_names=[], parent_id=None):
        from .user_group import UserGroup
        from .group import Group

        user = User(name=name, email=email, admin=admin, pi=pi, gdpr_consent=gdpr_consent, parent_id=parent_id)
        db.session.add(user)
        db.session.flush() # get inserted id

        groups = Group.query.filter(Group.name.in_(group_names)).all()

        for group in groups:
            db.session.add(UserGroup(user_id=user.id, group_id=group.id))

        db.session.commit()

        if user.is_service_account:
            APIKey.generate(user.id)

        return user

    @staticmethod
    def delete_user_account(user_id):
        from .user_group import UserGroup
        from .user_tos import UserTos
        from .user_custom_name import UserCustomName

        user = User.user_get_by_id(user_id)
        if user:
            UserGroup.query.filter_by(user_id=user_id).delete()
            UserTos.query.filter_by(user_id=user_id).delete()
            APIKey.query.filter_by(user_id=user_id).delete()
            UserCustomName.query.filter_by(user_id=user_id).delete()
            delete_all_tokens_for_user(user_id)
            db.session.delete(user)
            db.session.commit()

    @staticmethod
    def delete_service_account(sa_id):
        from .user_group import UserGroup
        sa = User.sa_get_by_id(sa_id)
        if sa:
            UserGroup.query.filter_by(user_id=sa_id).delete()
            APIKey.query.filter_by(user_id=sa_id).delete()
            delete_all_tokens_for_user(sa_id)
            db.session.delete(sa)
            db.session.commit()

    @staticmethod
    def get_by_id(id):
        return User.query.filter_by(id=id).first()

    @staticmethod
    def user_get_by_id(id):
        return User.query.filter_by(id=id).filter(User.parent_id.is_(None)).first()
    
    @staticmethod
    def sa_get_by_id(id):
        return User.query.filter_by(id=id).filter(User.parent_id.isnot(None)).first()
    
    @staticmethod
    def get_by_parent(id):
        return User.query.filter_by(parent_id=id).first()

    @staticmethod
    def get_normal_accounts():
        return User.query.filter(User.parent_id.is_(None)).order_by(User.id.asc())

    @staticmethod
    def get_all_service_accounts():
        return User.query.filter(User.parent_id.isnot(None)).order_by(User.id.asc()).all()
    
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def filter_by_ids(ids):
        if len(ids):
            return User.query.filter(User.id.in_(ids)).all()
        else:
            return [] # otherwise returns all users

    @staticmethod
    def search_by_email(email):
        return User.query.filter(User.email.ilike(f'%{email}%')).all()

    @staticmethod
    def filter_by_created(from_time=None, to_time=None):
        res = User.query.filter(User.parent_id.is_(None))

        if from_time is not None:
            res = res.filter(User.created >= func.to_timestamp(from_time))

        if to_time is not None:
            res = res.filter(User.created <= func.to_timestamp(to_time))

        try:
            return res.all()
        except sqlalchemy.exc.DataError:
            return []

    @staticmethod
    def search_by_name(name):
        return User.query.filter(User.parent_id.is_(None)).filter(User.name.ilike(f'%{name}%')).all()
    
    @staticmethod
    def sa_search_by_name(name):
        return User.query.filter(User.parent_id.isnot(None)).filter(User.name.ilike(f'%{name}%')).all()

    def update(self, data):
        user_fields = ['admin', 'name', 'pi', 'gdpr_consent', 'read_only']

        for field in user_fields:
            if field in data:
                setattr(self, field, data[field])

        db.session.commit()
        self.update_cache()

    def get_groups(self):
        # move to UserGroup
        from .group import Group
        from .user_group import UserGroup

        query = db.session.query(Group.id, Group.name)\
            .join(UserGroup, UserGroup.group_id == Group.id)\
            .filter(UserGroup.user_id == self.id)

        groups = query.all()

        return [{'id': id, 'name': name} for id, name in groups]

    def get_datasets_adminning(self):
        # move to DatasetAdmin
        from .dataset_admin import DatasetAdmin
        from .dataset import Dataset

        query = db.session.query(DatasetAdmin.dataset_id, Dataset.name)\
            .join(Dataset, DatasetAdmin.dataset_id == Dataset.id)\
            .filter(DatasetAdmin.user_id == self.id)
        
        datasets = query.all()
        
        return [{'id': dataset_id, 'name': dataset_name} for dataset_id, dataset_name in datasets]

    def datasets_missing_tos(self):
        from .group_dataset_permission import GroupDatasetPermission
        from .permission import Permission
        from .dataset import Dataset
        from .user_group import UserGroup
        from .user_tos import UserTos
        from .tos import Tos

        tos_user_id = self.parent_id if self.is_service_account else self.id

        query = db.session.query(Dataset.id, Dataset.name, Tos.id, Tos.name)\
            .join(GroupDatasetPermission, GroupDatasetPermission.dataset_id == Dataset.id)\
            .join(UserGroup, (UserGroup.group_id == GroupDatasetPermission.group_id) & (UserGroup.user_id == self.id))\
            .join(Permission, Permission.id == GroupDatasetPermission.permission_id)\
            .join(Tos, Tos.id == Dataset.tos_id)\
            .join(UserTos, (UserTos.tos_id == Tos.id) & (UserTos.user_id == tos_user_id), isouter=True)\
            .filter(UserTos.id == None)\
            .group_by(UserGroup.user_id, GroupDatasetPermission.dataset_id, Dataset.id, Tos.id)
        
        return [{'dataset_id': dataset_id, 'dataset_name': dataset_name, 'tos_id': tos_id, 'tos_name': tos_name}
            for dataset_id, dataset_name, tos_id, tos_name in query.distinct()]

    def _get_permissions(self):
        # messy dependencies, not sure if it should be moved
        from .group_dataset_permission import GroupDatasetPermission
        from .permission import Permission
        from .dataset import Dataset
        from .user_group import UserGroup
        from .user_tos import UserTos

        tos_user_id = self.parent_id if self.is_service_account else self.id

        query = db.session.query(GroupDatasetPermission.dataset_id, Dataset.name, Permission.name)\
            .join(UserGroup, (UserGroup.group_id == GroupDatasetPermission.group_id) & (UserGroup.user_id == self.id))\
            .join(Permission, Permission.id == GroupDatasetPermission.permission_id)\
            .join(Dataset, Dataset.id == GroupDatasetPermission.dataset_id)\
            .join(UserTos, (UserTos.tos_id == Dataset.tos_id) & (UserTos.user_id == tos_user_id), isouter=True)\
            .filter((Dataset.tos_id == None) | (UserTos.id != None))\
            .group_by(UserGroup.user_id, GroupDatasetPermission.dataset_id, Dataset.name, Permission.name)

        if self.read_only:
            query = query.filter(Permission.id != 2)

        #TODO: re-add read_only (filter by permission id if read_only is true)

        permissions = query.all()

        temp = {}

        for dataset_id, dataset_name, permission_name in permissions:
            temp[dataset_id] = temp.get(dataset_id, {'id': dataset_id, 'name': dataset_name, 'permissions': []})
            temp[dataset_id]['permissions'] += [permission_name]

        return temp.values()

    def create_cache(self):
        permissions = self._get_permissions()

        def permission_to_level(p):
            return {'none': 0, 'view': 1, 'edit': 2}.get(p, 0)

        return {
            'id': self.id,
            "parent_id": self.parent_id,
            "service_account": self.parent_id is not None,
            'name': self.public_name,
            'email': self.email,
            'admin': self.admin,
            'groups': [x['name'] for x in self.get_groups()],
            'permissions': {x['name']: max(map(permission_to_level, x['permissions'])) for x in permissions},
            'permissions_v2': {x['name']: x['permissions'] for x in permissions},
            'missing_tos': self.datasets_missing_tos(),
        }

    def generate_token(self, ex=None):
        user_json = json.dumps(self.create_cache())
        return insert_and_generate_unique_token(self.id, user_json, ex=ex)

    def get_service_account_token(self):
        tokens = r.smembers(self.tokens_key)

        for token_bytes in tokens: # should only be one
            return token_bytes.decode('utf-8')

    def get_service_accounts(self):
        return User.query.filter_by(parent_id=self.id).all()

    def update_cache(self):
        user_json = json.dumps(self.create_cache())

        tokens = r.smembers(self.tokens_key)

        for token_bytes in tokens:
            token = token_bytes.decode('utf-8')
            ttl = r.ttl("token_" + token) # update token without changing ttl

            if ttl == -2: # doesn't exist (expired)
                r.srem(self.tokens_key, token)
            else:
                ttl = ttl if ttl != -1 else None # -1 is no expiration (API KEYS)
                r.set("token_" + token, user_json, nx=False, ex=ttl)
