"""HTTP transport, retries, pagination and shared NVD rate limiting."""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import requests
from .metrics import Metrics, SourceClient
from .rate_limits import Cooldowns
from .http_retry import request
from .binary_download import download
from .http_cache import HttpCache

class Client:
    def __init__(self, timeout=30, proxy=None):
        self.metrics = Metrics()
        self.cancelled = threading.Event()
        self.cooldowns = Cooldowns(self.cancelled)
        self.cache = HttpCache()
        self.timeout = timeout
        self.proxy = proxy
        self.github_lock = threading.Lock()
        self.nvd_lock = threading.Lock()
        self.nvd_last = 0.0
        self.local = threading.local()
        self.sessions = []
        self.session_lock = threading.Lock()

    def for_source(self, source):
        self.metrics.add(source)
        return SourceClient(self, source)

    def request_parts(self, url, data):
        host = urllib.parse.urlparse(url).hostname
        headers = {'User-Agent': 'product-security-advisories/1.0', 'Accept': 'application/json'}
        if host == 'api.github.com':
            token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
            if token:
                headers['Authorization'] = 'Bearer ' + token
            headers['X-GitHub-Api-Version'] = '2022-11-28'
        if host == 'services.nvd.nist.gov' and os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        body = None if data is None else json.dumps(data).encode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
        return host, headers, body

    def throttle(self, host):
        self.cooldowns.check()
        self.cooldowns.wait(host)
        if host == 'services.nvd.nist.gov':
            with self.nvd_lock:
                interval = 0.7 if os.environ.get('NVD_API_KEY') else 6.2
                self.cooldowns.pause(max(0, interval - (time.monotonic() - self.nvd_last)))
                self.nvd_last = time.monotonic()

    def json(self, url, params=None, data=None, with_link=False, source="unscoped"):
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params, doseq=True)
        host, headers, body = self.request_parts(url, data)
        return request(self, url, source, lambda: self.open_json(url, body, headers, with_link, source))

    def bytes(self, url, source='unscoped', limit=16 * 1024 * 1024):
        return request(self, url, source, lambda: download(self, url, source, limit))

    def paginate_github(self, url, params=None):
        params = {**(params or {}), 'per_page': 100}
        visited = set()
        for _ in range(1000):
            batch, link = self.json(url, params, with_link=True)
            if not isinstance(batch, list):
                raise ValueError('Unexpected GitHub response')
            yield from batch
            next_link = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not next_link:
                return
            url = next_link.group(1)
            if urllib.parse.urlparse(url).hostname != 'api.github.com' or url in visited:
                raise RuntimeError('Invalid or repeated GitHub pagination URL')
            visited.add(url)
            params = None
        raise RuntimeError('GitHub pagination safety limit reached; checkpoint not advanced')




    def session(self):
        if not hasattr(self.local, 'session'):
            session = requests.Session()
            self.local.session = session
            with self.session_lock:
                self.sessions.append(session)
        return self.local.session

    def cancel(self):
        self.cancelled.set()

    def close(self):
        for session in self.sessions:
            session.close()
        self.sessions.clear()
        self.local = threading.local()

    def open_json(self, url, body, headers, with_link, source='unscoped'):
        headers = dict(headers)
        key, entry = self.cache.prepare(url, headers, body, source)
        proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
        self.metrics.add(source, requests=1)
        try:
            with self.session().request('GET' if body is None else 'POST', url,
                                        data=body, headers=headers, proxies=proxies,
                                        timeout=self.timeout) as response:
                return self.decode_response(response, url, with_link, source, key, entry)
        except requests.RequestException as exc:
            self.metrics.add(source, http_errors=1)
            raise urllib.error.URLError(type(exc).__name__) from None

    def decode_response(self, response, url, with_link, source, key=None, entry=None):
        bodies = [*response.history, response]
        self.metrics.add(source, requests=len(response.history),
                         response_bytes=sum(len(item.content) for item in bodies),
                         not_modified=int(response.status_code == 304))
        if response.status_code >= 400:
            self.metrics.add(source, http_errors=1)
            raise urllib.error.HTTPError(url, response.status_code, response.text[:512], response.headers, None)
        result, link = self.cache.decode(response, key, entry, source)
        return (result, link) if with_link else result
