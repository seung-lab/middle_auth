from .base import db

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