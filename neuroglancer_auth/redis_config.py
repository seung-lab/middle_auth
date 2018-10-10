import os

redis_config = dict(
    HOST=os.environ.get('REDISHOST', 'localhost'),
    PORT=int(os.environ.get('REDISPORT', 6379))
)
