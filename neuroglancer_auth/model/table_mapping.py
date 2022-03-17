from .base import db

from sqlalchemy.orm import relationship

from .dataset import Dataset

class ServiceTable(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_name = db.Column(db.String(120), nullable=False)
    table_name = db.Column(db.String(120), nullable=False)
    dataset_id = db.Column('dataset_id', db.Integer, db.ForeignKey("dataset.id"), nullable=False)
    contact_name = db.Column(db.String(120), unique=False, nullable=False)
    contact_email = db.Column(db.String(120), unique=False, nullable=False)

    __table_args__ = (db.UniqueConstraint("service_name", "table_name"),)

    dataset = relationship(Dataset)

    def __repr__(self):
        return self.name

    @staticmethod
    def get_dataset_by_service_table(service, table):
        el = ServiceTable.query.filter_by(service_name=service, table_name=table).first()
        if el:
            return el.dataset.name
