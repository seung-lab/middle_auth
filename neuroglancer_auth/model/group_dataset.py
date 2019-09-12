from .base import db
from .group import Group
from .dataset import Dataset

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
    
    @staticmethod
    def get_permissions_for_group(group_id):
        query = db.session.query(GroupDataset.dataset_id, Dataset.name, GroupDataset.level)\
            .join(Dataset, Dataset.id == GroupDataset.dataset_id)\
            .filter(GroupDataset.group_id == group_id)\
            .order_by(GroupDataset.dataset_id.asc())

        permissions = query.all()

        return [{'id': dataset_id, 'name': dataset_name, 'level': level} for dataset_id, dataset_name, level in permissions]

    @staticmethod
    def get_all_group_permissions(dataset_id):
        query = db.session.query(GroupDataset.group_id, Group.name, GroupDataset.level)\
            .join(Group, Group.id == GroupDataset.group_id)\
            .filter(GroupDataset.dataset_id == dataset_id)

        permissions = query.all()

        return [{'id': group_id, 'name': group_name, 'level': level} for group_id, group_name, level in permissions]
