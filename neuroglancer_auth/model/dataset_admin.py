from .base import db
from .dataset import Dataset
from .user import User

class DatasetAdmin(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    dataset_id = db.Column('dataset_id', db.Integer, db.ForeignKey("dataset.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "dataset_id"),)

    @staticmethod
    def exists(user_id, dataset_id):
        query = DatasetAdmin.query.filter_by(user_id=user_id, dataset_id=dataset_id).exists()
        return db.session.query(query).scalar()

    @staticmethod
    def add(user_id, dataset_id):
        da = DatasetAdmin(user_id=user_id, dataset_id=dataset_id)
        db.session.add(da)
        db.session.commit()

    @staticmethod
    def remove(user_id, dataset_id):
        DatasetAdmin.query.filter_by(user_id=user_id, dataset_id=dataset_id).delete()
        db.session.commit()

    @staticmethod
    def get_all_by_user(user_id):
        datasets = db.session.query(Dataset)\
            .filter(Dataset.id == DatasetAdmin.dataset_id)\
            .filter(DatasetAdmin.user_id == user_id).all()

        return datasets

    @staticmethod
    def get_all_by_dataset(dataset_id):
        users = db.session.query(DatasetAdmin.user_id, User.name)\
            .filter(DatasetAdmin.user_id == User.id)\
            .filter(DatasetAdmin.dataset_id == self.id).all()

        return [{"id": id, "name": name} for (id, name) in users]
