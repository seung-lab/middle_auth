from .base import db, r

from sqlalchemy import text

import json
import secrets

class App(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    url = db.Column(db.String(128), unique=True, nullable=False)

    @staticmethod
    def is_verified_url(url):
        safe_url = text(url)
        return App.query.filter(f"{safe_url} ~ url").exists()
