from .base import db

from sqlalchemy.sql import func

class UserAssociation(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    association_id = db.Column('association_id', db.Integer, db.ForeignKey("association.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "association_id"),)
    start = db.Column(db.DateTime, server_default=func.now(), nullable=True)
    end = db.Column(db.DateTime, nullable=True)

class Association(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return self.name
