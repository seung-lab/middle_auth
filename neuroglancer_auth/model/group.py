from .base import db

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return self.name

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
            return Group.query.order_by(Group.id.asc()).all()

    @staticmethod
    def add(name):
        group = Group(name=name)
        db.session.add(group)
        db.session.commit()
        return group

    def update_cache(self):
        # move to UserGroup
        from .user import User
        from .user_group import UserGroup

        users = UserGroup.get_users(self.id)

        for user in users:
            user.update_cache()
