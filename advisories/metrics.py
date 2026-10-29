"""Thread-safe, source-attributed counters; bytes are decoded HTTP response bodies."""
import threading

FIELDS = ('requests', 'response_bytes', 'retries', 'http_errors', 'cache_hits',
          'not_modified', 'new', 'changed', 'unchanged', 'removed')


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.sources = {}

    def add(self, source, **values):
        with self.lock:
            counters = self.sources.setdefault(source, dict.fromkeys(FIELDS, 0))
            for key, value in values.items():
                counters[key] += value

    def snapshot(self):
        with self.lock:
            return {source: dict(values) for source, values in sorted(self.sources.items())}


class SourceClient:
    def __init__(self, client, source):
        self.client = client
        self.source = source

    def json(self, url, params=None, data=None, with_link=False):
        return self.client.json(url, params=params, data=data, with_link=with_link, source=self.source)

    def paginate_github(self, url, params=None):
        from .http_client import Client
        yield from Client.paginate_github(self, url, params)

    def cache_hit(self, count=1):
        self.client.metrics.add(self.source, cache_hits=count)


def cache_hit(client, count=1):
    callback = getattr(client, 'cache_hit', None)
    if callback:
        callback(count)
