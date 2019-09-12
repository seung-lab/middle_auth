from .base import db

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
    def get_all_by_admin(user_id):
        # move to DatasetAdmin ... still doesn't solve import
        # user shouldn't need to known about datasets
        from .dataset_admin import DatasetAdmin

        datasets = db.session.query(Dataset)\
            .filter(Dataset.id == DatasetAdmin.dataset_id)\
            .filter(DatasetAdmin.user_id == user_id).all()

        return datasets

    @staticmethod
    def add(name):
        dataset = Dataset(name=name)
        db.session.add(dataset)
        db.session.commit()
        return dataset

    def get_admins(self):
        # move to DatasetAdmin ... still doesn't solve import
        # user shouldn't need to known about datasets
        from .dataset_admin import DatasetAdmin
        from .user import User

        users = db.session.query(DatasetAdmin.user_id, User.name)\
            .filter(DatasetAdmin.user_id == User.id)\
            .filter(DatasetAdmin.dataset_id == self.id).all()

        return [{"id": id, "name": name} for (id, name) in users]

    def get_permissions(self):
        # todo, move to GroupDataset
        from .group_dataset import GroupDataset
        from .group import Group

        query = db.session.query(GroupDataset.group_id, Group.name, GroupDataset.level)\
            .join(Group, Group.id == GroupDataset.group_id)\
            .filter(GroupDataset.dataset_id == self.id)
        
        permissions = query.all()

        return [{'id': group_id, 'name': group_name, 'level': level} for group_id, group_name, level in permissions]
