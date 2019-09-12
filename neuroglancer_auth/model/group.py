from .base import db
from .dataset import Dataset

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
        }

    @staticmethod
    def get_by_id(id):
        return Group.query.filter_by(id=id).first()

    @staticmethod
    def search_by_name(name):
        if name:
            return Group.query.filter(Group.name.ilike(f'%{name}%')).all()
        else:
            return Group.query.all()

    @staticmethod
    def add(name):
        group = Group(name=name)
        db.session.add(group)
        db.session.commit()
        return group

    def update_cache(self):
        # move to UserGroup
        from .user import User

        users = self.get_users()

        for user in users:
            User.get_by_id(user["id"]).update_cache()
