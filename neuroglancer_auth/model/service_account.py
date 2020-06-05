from .base import db, r
from .api_key import insert_and_generate_unique_token

import json
from sqlalchemy.sql import func

class ServiceAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(80), unique=True, nullable=False) # public
    read_only = db.Column(db.Boolean, server_default="0", nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
        }

    @staticmethod
    def create_account(user_id, name, group_names=[]):
        from .service_account_group import ServiceAccountGroup
        from .group import Group

        sa = ServiceAccount(user_id=user_id, name=name)
        db.session.add(sa)
        db.session.flush() # get inserted id

        groups = Group.query.filter(Group.name.in_(group_names)).all()

        for group in groups:
            db.session.add(ServiceAccountGroup(sa_id=sa.id, group_id=group.id))

        db.session.commit()

        sa.load_into_cache()

        return sa

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
        user_fields = ['name']

        for field in user_fields:
            if field in data:
                setattr(self, field, data[field])

        db.session.commit()
        self.update_cache()

    @staticmethod
    def remove(sa_id):
        from .service_account_group import ServiceAccountGroup
        ServiceAccountGroup.query.filter_by(sa_id=sa_id).delete()
        sa = ServiceAccount.query.filter_by(id=sa_id)
        sa.delete_cache()
        sa.delete()
        db.session.commit()

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

    def create_cache(self):
        return {
            'id': self.id,
            'name': self.name,
            'groups': [x['name'] for x in self.get_groups()],
            'permissions': {x['name']: x['level'] for x in self.get_permissions()},
        }

    def delete_cache(self):
        tokens_key = "sa_tokens_" + str(self.id)
        tokens = r.smembers(tokens_key)

        for token_bytes in tokens:
            token = token_bytes.decode('utf-8')
            token_key = "token_" + token
            p = r.pipeline()
            p.delete(token_key)
            p.srem(tokens_key, token)
            p.execute()

    def load_into_cache(self):
        sa_json = json.dumps(self.create_cache())
        tokens_key = "sa_tokens_" + str(self.id)
        return insert_and_generate_unique_token(tokens_key, sa_json)

    def update_cache(self):
        sa_json = json.dumps(self.create_cache())
        tokens_key = "sa_tokens_" + str(self.id)

        tokens = r.smembers(tokens_key)

        for token_bytes in tokens:
            token = token_bytes.decode('utf-8')
            token_key = "token_" + token
            ttl = r.ttl(token_key) # update token without changing ttl

            if ttl == -2: # doesn't exist (expired)
                r.srem(tokens_key, token)
            else:
                ttl = ttl if ttl != -1 else None # -1 is no expiration (API KEYS)
                r.set(token_key, sa_json, nx=False, ex=ttl)
