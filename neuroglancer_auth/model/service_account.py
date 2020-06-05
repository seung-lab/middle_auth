from .base import db, r

import json
from sqlalchemy.sql import func

class ServiceAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(80), unique=False, nullable=False) # public
    created = db.Column(db.DateTime, server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "email": self.email,
            "admin": self.admin,
            "pi": self.pi,
            "gdpr_consent": self.gdpr_consent,
            "admin_datasets": self.get_datasets_adminning()
        }

    @staticmethod
    def create_account(user_id, name, group_names=[]):
        from .service_account_group import ServiceAccountGroup
        from .group import Group

        user = ServiceAccount(user_id=user_id, name=name)
        db.session.add(user)
        db.session.flush() # get inserted id

        groups = Group.query.filter(Group.name.in_(group_names)).all()

        for group in groups:
            db.session.add(ServiceAccountGroup(user_id=user.id, group_id=group.id))

        db.session.commit()
        return user

    @staticmethod
    def get_by_id(id):
        return ServiceAccount.query.filter_by(id=id).first()
    
    @staticmethod
    def filter_by_ids(ids):
        return ServiceAccount.query.filter(ServiceAccount.id.in_(ids)).all()

    @staticmethod
    def search_by_name(name):
        return ServiceAccount.query.filter(ServiceAccount.name.ilike(f'%{name}%')).all()

    def update(self, data):
        user_fields = ['admin', 'name', 'pi', 'gdpr_consent']

        for field in user_fields:
            if field in data:
                setattr(self, field, data[field])

        db.session.commit()
        self.update_cache()

    def get_groups(self):
        # move to ServiceAccountGroup
        from .group import Group
        from .service_account_group import ServiceAccountGroup

        query = db.session.query(Group.id, Group.name)\
            .join(ServiceAccountGroup, ServiceAccountGroup.group_id == Group.id)\
            .filter(ServiceAccountGroup.sa_id == self.id)

        groups = query.all()

        return [{'id': id, 'name': name} for id, name in groups]

    def get_permissions(self):
        # messy dependencies, not sure if it should be moved
        from .group_dataset import GroupDataset
        from .dataset import Dataset
        from .service_account_group import ServiceAccountGroup

        query = db.session.query(GroupDataset.dataset_id, Dataset.name, func.max(GroupDataset.level))\
            .join(ServiceAccountGroup, ServiceAccountGroup.group_id == GroupDataset.group_id)\
            .join(Dataset, Dataset.id == GroupDataset.dataset_id)\
            .filter(ServiceAccountGroup.sa_id == self.id)\
            .group_by(ServiceAccountGroup.sa_id, GroupDataset.dataset_id, Dataset.name)
        
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
            'groups': [x['name'] for x in self.get_groups()],
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
