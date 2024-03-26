from neuroglancer_auth.model.tos import Tos
from .base import db
from .tos import Tos

from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

class UserTos(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    tos_id = db.Column('tos_id', db.Integer, db.ForeignKey("tos.id"), nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    __table_args__ = (db.UniqueConstraint("user_id", "tos_id"),)

    #  these relationships are only added for flask_admin
    user = relationship("User", overlaps="tos,users")
    affiliation = relationship("Tos", overlaps="tos,users")

    @staticmethod
    def get(user_id, tos_id):
        return UserTos.query.filter_by(user_id=user_id, tos_id=tos_id).first()

    @staticmethod
    def add(user_id, tos_id):
        from .user import User

        el = UserTos(user_id=user_id, tos_id=tos_id)
        db.session.add(el)
        db.session.commit()

        user = User.get_by_id(user_id)
        user.update_cache()
        # service accounts use the parent user's tos record
        service_accounts = user.get_service_accounts()

        for sa in service_accounts:
            sa.update_cache()

    @staticmethod
    def get_tos_by_user(user_id):
        toses = db.session.query(UserTos.tos_id, Tos.name)\
            .filter(UserTos.tos_id == Tos.id)\
            .filter(UserTos.user_id == user_id)\
            .all()

        return [{'id': tos_id, 'name': name} for tos_id, name in toses]
