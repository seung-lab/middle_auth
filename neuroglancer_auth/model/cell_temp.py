from .base import db

class CellTemp(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    table_id = db.Column('table_id', db.Integer, nullable=False)
    cell_id = db.Column('cell_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    public = db.Column(db.Boolean, server_default="0", nullable=False)
    __table_args__ = (db.UniqueConstraint("table_id", "cell_id"),)

    @staticmethod
    def is_public(table_id, cell_id):
        query = CellTemp.query.filter_by(table_id=table_id, cell_id=cell_id, public=True).exists()
        return db.session.query(query).scalar()

    def as_dict(self):
        res = {
            "id": self.id,
            "table_id": self.table_id,
            "cell_id": self.cell_id,
            "public": self.public,
        }

        return res
