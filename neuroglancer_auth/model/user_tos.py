from neuroglancer_auth.model.tos import Tos
from .base import db
from .tos import Tos

from sqlalchemy.sql import func

class UserTos(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    tos_id = db.Column('tos_id', db.Integer, db.ForeignKey("tos.id"), nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    __table_args__ = (db.UniqueConstraint("user_id", "tos_id"),)

    @staticmethod
    def get(tos_id, user_id):
        return UserTos.query.filter_by(user_id=user_id, tos_id=tos_id).first()

    @staticmethod
    def add(user_id, tos_id):
        el = UserTos(user_id=user_id, tos_id=tos_id)
        db.session.add(el)
        db.session.commit()

    @staticmethod
    def get_tos(user_id):
        toses = db.session.query(UserTos.tos_id, Tos.name)\
            .filter(UserTos.tos_id == Tos.id)\
            .filter(UserTos.user_id == user_id)\
            .all()

        return [{'id': tos_id, 'name': name} for tos_id, name in toses]

    # @staticmethod
    # def get_service_accounts(group_id):
    #     users = db.session.query(UserGroup.user_id, User.name)\
    #         .filter(UserGroup.user_id == User.id)\
    #         .filter(UserGroup.group_id == group_id)\
    #         .filter(User.parent_id.isnot(None))\
    #         .all()

    #     return [{'id': user_id, 'name': name} for user_id, name in users]


    # @staticmethod
    # def get_admins(group_id):
    #     users = db.session.query(UserGroup.user_id, User.name)\
    #         .filter(UserGroup.admin == True)\
    #         .filter(UserGroup.user_id == User.id)\
    #         .filter(UserGroup.group_id == group_id).all()

    #     return [{'id': user_id, 'name': name} for user_id, name in users]

    # def delete(self):
    #     db.session.delete(self)
    #     db.session.commit()
    #     user = User.get_by_id(self.user_id).update_cache()

    # def update(self, data):
    #     if 'admin' in data:
    #         self.admin = data['admin']

    #     db.session.commit()
