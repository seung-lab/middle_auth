from .base import db

import sqlalchemy
from sqlalchemy.sql import func

from psycopg2.errorcodes import UNIQUE_VIOLATION
from psycopg2 import errors


class UserCustomName(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, unique=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    name = db.Column(db.String(80), unique=False, nullable=False) # public
    active = db.Column(db.Boolean, server_default="1", nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    @staticmethod
    def get(user_id, show_all=False):
        query = UserCustomName.query.filter_by(user_id=user_id)

        if not show_all:
            query = query.filter_by(active=True)

        return query.first()

    @staticmethod
    def add(user_id, name):
        try:
            el = UserCustomName(user_id=user_id, name=name)
            db.session.add(el)
            db.session.commit()
            return True
        except sqlalchemy.exc.IntegrityError as err:
            db.session.rollback()
            return False

    @staticmethod
    def maybe_deactive(user_id):
        el = UserCustomName.get(user_id)

        if el:
            el.active = False
            db.session.commit()
