"""Respect service cooldowns across tasks, without delaying unrelated hosts."""
import email.utils
import threading
import time


def retry_after(value, now):
    try:
        return max(0, float(value))
    except (ValueError, TypeError):
        try:
            return max(0, email.utils.parsedate_to_datetime(value).timestamp() - now)
        except (ValueError, TypeError, OverflowError):
            return None


def limited(error):
    headers = error.headers or {}
    return error.code == 429 or (error.code == 403 and (
        headers.get('Retry-After') is not None or headers.get('X-RateLimit-Remaining') == '0'
        or 'secondary rate limit' in str(error.reason).lower()))


def delay(error, attempt):
    headers = error.headers or {}
    after = retry_after(headers.get('Retry-After'), time.time())
    if after is not None:
        return after
    if headers.get('X-RateLimit-Remaining') == '0':
        try:
            return max(0, float(headers['X-RateLimit-Reset']) - time.time()) + 1
        except (KeyError, ValueError):
            pass
    return 60 * 2 ** attempt if limited(error) else min(30, 2 ** (attempt + 1))


class Cooldowns:
    def __init__(self):
        self.lock = threading.Lock()
        self.deadlines = {}

    def defer(self, host, seconds):
        with self.lock:
            self.deadlines[host] = max(self.deadlines.get(host, 0), time.monotonic() + seconds)

    def wait(self, host):
        with self.lock:
            seconds = max(0, self.deadlines.get(host, 0) - time.monotonic())
        if seconds:
            time.sleep(seconds)


def retry_http(cooldowns, host, error, attempt):
    is_limit = limited(error)
    if is_limit:
        cooldowns.defer(host, delay(error, attempt))
    if attempt >= 2:
        return False
    if is_limit:
        return True
    if error.code in (500, 502, 503, 504):
        time.sleep(delay(error, attempt))
        return True
    return False
