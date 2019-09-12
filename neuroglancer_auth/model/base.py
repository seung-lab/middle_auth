# import json
# import secrets
import redis
import os

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

r = redis.Redis(
        host=os.environ.get('REDISHOST', 'localhost'),
        port=int(os.environ.get('REDISPORT', 6379)))

