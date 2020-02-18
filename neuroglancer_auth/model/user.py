from .base import db, r

import json

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=False, nullable=False) # public
    email = db.Column(db.String(120), unique=True, nullable=False) # public + affiliation
    admin = db.Column(db.Boolean, server_default="0", nullable=False)
    gdpr_consent = db.Column(db.Boolean, server_default="0", nullable=False)
    pi = db.Column(db.String(80), server_default="", nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "admin": self.admin,
            "pi": self.pi,
            "gdpr_consent": self.gdpr_consent,
            "admin_datasets": self.get_datasets_adminning()
        }

    @staticmethod
    def create_account(email, name, pi, admin=False, gdpr_consent=False, group_names=[]):
        from .user_group import UserGroup
        from .group import Group

        user = User(name=name, email=email, admin=admin, pi=pi, gdpr_consent=gdpr_consent)
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
    def filter_by_ids(ids):
        if len(ids):
            return User.query.filter(User.id.in_(ids)).all()
        else:
            return [] # otherwise returns all users

    @staticmethod
    def search_by_email(email):
        return User.query.filter(User.email.ilike(f'%{email}%')).all()

    @staticmethod
    def search_by_name(name):
        return User.query.filter(User.name.ilike(f'%{name}%')).all()

    def update(self, data):
        user_fields = ['admin', 'name', 'pi', 'gdpr_consent']

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

    def get_permissions(self):
        # messy dependencies, not sure if it should be moved
        from .group_dataset import GroupDataset
        from .dataset import Dataset
        from .user_group import UserGroup

        query = db.session.query(GroupDataset.dataset_id, Dataset.name, GroupDataset.level)\
            .join(UserGroup, UserGroup.group_id == GroupDataset.group_id)\
            .join(Dataset, Dataset.id == GroupDataset.dataset_id)\
            .filter(UserGroup.user_id == self.id)
        
        permissions = query.all()
        
        return [{'id': dataset_id, 'name': dataset_name, 'level': level} for dataset_id, dataset_name, level in permissions]

    def get_datasets_adminning(self):
        # move to DatasetAdmin
        from .dataset_admin import DatasetAdmin
        from .dataset import Dataset

        query = db.session.query(DatasetAdmin.dataset_id, Dataset.name)\
            .join(Dataset, DatasetAdmin.dataset_id == Dataset.id)\
            .filter(DatasetAdmin.user_id == self.id)
        
        datasets = query.all()
        
        return [{'id': dataset_id, 'name': dataset_name} for dataset_id, dataset_name in datasets]

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
