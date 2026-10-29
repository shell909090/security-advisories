"""Bounded conditional GET cache, keyed by request representation and auth context."""
import copy
import json
import threading
import time
from .records import digest


class HttpCache:
    def __init__(self, entries=None):
        self.entries = copy.deepcopy(entries or {})
        self.lock = threading.Lock()

    def prepare(self, url, headers, body, source):
        eligible = source in ('ghsa', 'project') or (source == 'cve' and url.endswith('/deltaLog.json'))
        if body is not None or not eligible:
            return None, None
        key = digest({'url': url, 'headers': headers})
        with self.lock:
            entry = copy.deepcopy(self.entries.get(key))
        if entry and 'body' in entry:
            validator = entry.get('etag')
            if validator:
                headers['If-None-Match'] = validator
            elif entry.get('last_modified'):
                headers['If-Modified-Since'] = entry['last_modified']
        return key, entry

    def decode(self, response, key, entry, source):
        if response.status_code == 304:
            if key is None or not entry or 'body' not in entry:
                raise ValueError('HTTP 304 without a complete cached response')
            entry['used_at'] = time.time()
            with self.lock:
                self.entries[key] = entry
            return copy.deepcopy(entry['body']), entry.get('link', '')
        result = json.loads(response.content)
        link = response.headers.get('Link', '')
        if key is not None:
            self.store(key, response, result, link, source)
        return result, link

    def store(self, key, response, result, link, source):
        etag = response.headers.get('ETag')
        modified = response.headers.get('Last-Modified')
        with self.lock:
            self.entries.pop(key, None)
            if etag or modified:
                self.entries[key] = dict(body=copy.deepcopy(result), link=link, etag=etag,
                                         last_modified=modified, source=source, used_at=time.time())

    def snapshot(self, previous, failed):
        entries = {key: value for key, value in previous.items() if value['source'] in failed}
        with self.lock:
            entries.update({key: value for key, value in self.entries.items() if value['source'] not in failed})
        ordered = sorted(entries, key=lambda key: entries[key]['used_at'], reverse=True)
        return {key: entries[key] for key in ordered[:512]}
