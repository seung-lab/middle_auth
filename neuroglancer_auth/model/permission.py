from .base import db

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
        }

    @staticmethod
    def get_by_id(id):
        return Permission.query.filter_by(id=id).first()

    @staticmethod
    def search_by_name(name):
        if name:
            return Permission.query.filter(Permission.name.ilike(f'%{name}%')).all()
        else:
            return Permission.query.order_by(Permission.id.asc()).all()

    @staticmethod
    def add(name):
        el = Permission(name=name)
        db.session.add(el)
        db.session.commit()
        return el
