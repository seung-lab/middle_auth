from .base import db

class CellTemp(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dataset_id = db.Column('dataset_id', db.Integer, db.ForeignKey("dataset.id"), nullable=False)
    cell_id = db.Column('cell_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    public = db.Column(db.Boolean, server_default="0", nullable=False)
    __table_args__ = (db.UniqueConstraint("dataset_id", "cell_id"),)

    @staticmethod
    def is_public(dataset_id, cell_id):
        query = CellTemp.query.filter_by(dataset_id=dataset_id, cell_id=cell_id, public=True).exists()
        return db.session.query(query).scalar()
