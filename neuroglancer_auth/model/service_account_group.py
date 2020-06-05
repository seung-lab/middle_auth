from .base import db
from .serviceaccount import ServiceAccount
from .group import Group

from flask_sqlalchemy import event

class ServiceAccountGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sa_id = db.Column('sa_id', db.Integer, db.ForeignKey("serviceaccount.id"), nullable=False)
    group_id = db.Column('group_id', db.Integer, db.ForeignKey("group.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("sa_id", "group_id"),)

    @staticmethod
    def get(group_id, sa_id):
        return ServiceAccountGroup.query.filter_by(group_id=group_id, sa_id=sa_id).first()

    @staticmethod
    def add(sa_id, group_id, admin=False):
        ug = ServiceAccountGroup(sa_id=sa_id, group_id=group_id, admin=admin)
        db.session.add(ug)
        db.session.commit()
        sa = ServiceAccount.get_by_id(sa_id)
        sa.update_cache()

    @staticmethod
    def get_users(group_id):
        users = db.session.query(ServiceAccountGroup.sa_id, ServiceAccount.name)\
            .filter(ServiceAccountGroup.sa_id == ServiceAccount.id)\
            .filter(ServiceAccountGroup.group_id == group_id).all()

        return [{'id': user_id, 'name': name, 'admin': admin} for user_id, name, admin in users]

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        user = ServiceAccount.get_by_id(self.sa_id).update_cache()
