from .base import db

class App(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    url = db.Column(db.String(128), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "url": self.url,
        }
    
    @staticmethod
    def get_all(self):
        return App.query.order_by(App.id.asc()).all()
