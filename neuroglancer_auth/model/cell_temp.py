from .base import db

class CellTemp(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    table_id = db.Column('table_id', db.String(120), nullable=False)
    root_id = db.Column('root_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    public = db.Column(db.Boolean, server_default="0", nullable=False)
    __table_args__ = (db.UniqueConstraint("table_id", "root_id"),)

    @staticmethod
    def is_public(table_id, root_id):
        query = CellTemp.query.filter_by(table_id=table_id, root_id=root_id, public=True).exists()
        return db.session.query(query).scalar()
