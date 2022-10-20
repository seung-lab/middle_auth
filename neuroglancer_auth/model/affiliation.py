from .base import db

from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

class UserAffiliation(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    affiliation_id = db.Column('affiliation_id', db.Integer, db.ForeignKey("affiliation.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "affiliation_id"),)
    start = db.Column(db.DateTime, server_default=func.now(), nullable=True)
    end = db.Column(db.DateTime, nullable=True)

    #  these relationships are only added for flask_admin
    user = relationship("User", overlaps="affiliations,users")
    affiliation = relationship("Affiliation", overlaps="affiliations,users")

    def as_dict(self):
        return {
            "id": self.affiliation_id,
            "name": self.affiliation.name,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }

class Affiliation(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    contact_name = db.Column(db.String(120), unique=False, nullable=True)
    contact_email = db.Column(db.String(120), unique=False, nullable=True)

    def __repr__(self):
        return self.name
