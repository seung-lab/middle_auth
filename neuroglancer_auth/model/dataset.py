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
    
    def update_cache(self):
        from .group_dataset_permission import GroupDatasetPermission

        groups = GroupDatasetPermission.get_groups_by_dataset(self.id)

        for group in groups:
            group.update_cache() # TODO, avoid duplication if user belongs to dataset through multiple groups

    def update(self, data):
        fields = ['name', 'tos_id']

        for field in fields:
            if field in data:
                setattr(self, field, data[field])

        db.session.commit()
        self.update_cache()
