from .base import db

class App(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    url = db.Column(db.String(128), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "url": self.url,
        }

    def __repr__(self):
        return self.url

    @staticmethod
    def get_all_dict():
        return [app.as_dict() for app in App.query.order_by(App.id.asc()).all()]
