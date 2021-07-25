from functools import wraps
import time

class RateLimitError(Exception):
    pass

def rate_limit(limit_args=[0], limit_kwargs=[], limit=20, window_sec=60 * 60):
    activity = {}
    window_start = time.time()

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            nonlocal window_start
            nonlocal activity
            now = time.time()
            elapsed_time_sec = now - window_start

            # reset store if window passed
            if elapsed_time_sec > window_sec:
                activity = {}
                window_start = now

            key_args = tuple(args[x] for x in limit_args)
            key_kwargs = tuple(kwargs[x] for x in limit_kwargs)

            key = (key_args, key_kwargs)

            # increment rate
            current_rate = activity.get(key, 0) + 1
            activity[key] = current_rate

            if current_rate > limit:
                raise RateLimitError()
            else:
                return f(*args, **kwargs)

        return decorated_function
    return decorator
