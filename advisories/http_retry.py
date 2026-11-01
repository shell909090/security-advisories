"""Retry policy shared by JSON and bounded binary downloads."""
import contextlib
import time
import urllib.error
import urllib.parse
from .rate_limits import retry_http


def request(client, url, source, operation):
    host = urllib.parse.urlparse(url).hostname
    gate = client.github_lock if host == 'api.github.com' else contextlib.nullcontext()
    for attempt in range(3):
        client.cooldowns.check()
        client.metrics.add(source, retries=int(attempt > 0))
        try:
            with gate:
                client.throttle(host)
                return operation()
        except urllib.error.HTTPError as exc:
            if retry_http(client.cooldowns, host, exc, attempt):
                continue
            raise RuntimeError(f'HTTP {exc.code}: {host}{urllib.parse.urlparse(url).path}') from None
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < 2:
                client.cooldowns.pause(2 ** attempt)
                continue
            raise RuntimeError(f'Network failure: {host} ({type(exc).__name__})') from None
