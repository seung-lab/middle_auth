import redis
import os

class Config(object):
	SECRET_KEY = 'test'
	SESSION_TYPE = 'redis'
	SESSION_REDIS = redis.from_url('redis://' + os.environ.get('REDISHOST', 'localhost') + ':' + str(os.environ.get('REDISPORT', 6379)))
	SQLALCHEMY_DATABASE_URI = "postgresql://postgres:uhkbjFPhnmtriotd@10.220.176.4/test1"
	SQLALCHEMY_TRACK_MODIFICATIONS = False
