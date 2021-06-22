from .base import db, r

# import json
from sqlalchemy.sql import func
# import sqlalchemy

class Tos(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    linkText = db.Column(db.Text, unique=False, nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    def as_dict(self):
        res = {
            "id": self.id,
            "name": self.name,
            "linkText": self.linkText,
        }

        return res

    # @property
    # def is_service_account(self):
    #     return self.parent_id is not None

    @staticmethod
    def get_by_id(id):
        return Tos.query.filter_by(id=id).first()

    @staticmethod
    def add(name, linkText):
        el = Tos(name=name, linkText=linkText)
        db.session.add(el)
        db.session.commit()
        return el

    @staticmethod
    def search_by_name(name):
        if name:
            return Tos.query.filter(Tos.name.ilike(f'%{name}%')).all()
        else:
            return Tos.query.order_by(Tos.id.asc()).all()


    # @staticmethod
    # def get_by_email(email):
    #     return User.query.filter_by(email=email).first()

    # @staticmethod
    # def filter_by_ids(ids):
    #     return User.query.filter(User.id.in_(ids)).all()

    # def update(self, data):
    #     user_fields = ['admin', 'name', 'pi', 'gdpr_consent', 'read_only']

    #     for field in user_fields:
    #         if field in data:
    #             setattr(self, field, data[field])

    #     db.session.commit()
    #     self.update_cache()
