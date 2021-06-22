from .base import db

class Dataset(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    tos_id = db.Column('tos_id', db.Integer, db.ForeignKey("tos.id"), nullable=True)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "tos_id": self.tos_id,
        }

    @staticmethod
    def get_by_id(id):
        return Dataset.query.filter_by(id=id).first()

    @staticmethod
    def search_by_name(name):
        if name:
            return Dataset.query.filter(Dataset.name.ilike(f'%{name}%')).all()
        else:
            return Dataset.query.all()

    @staticmethod
    def add(name):
        dataset = Dataset(name=name)
        db.session.add(dataset)
        db.session.commit()
        return dataset
