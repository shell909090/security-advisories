"""HTTP transport, retries, pagination and shared NVD rate limiting."""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

class Client:
    def __init__(self, timeout=30, proxy=None):
        self.timeout = timeout
        self.proxy = proxy
        self.nvd_lock = threading.Lock()
        self.nvd_last = 0.0

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
        if host == 'services.nvd.nist.gov':
            with self.nvd_lock:
                interval = 0.7 if os.environ.get('NVD_API_KEY') else 6.2
                time.sleep(max(0, interval - (time.monotonic() - self.nvd_last)))
                self.nvd_last = time.monotonic()

    def json(self, url, params=None, data=None, with_link=False):
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params, doseq=True)
        host, headers, body = self.request_parts(url, data)
        for attempt in range(3):
            self.throttle(host)
            try:
                return self.open_json(url, body, headers, with_link)
            except urllib.error.HTTPError as exc:
                if attempt < 2 and exc.code in (429, 500, 502, 503, 504):
                    time.sleep(min(30, 2 ** (attempt + 1)))
                    continue
                raise RuntimeError(f'HTTP {exc.code}: {host}{urllib.parse.urlparse(url).path}') from None
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f'Network failure: {host} ({type(exc).__name__})') from None

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




    def open_json(self, url, body, headers, with_link):
        request = urllib.request.Request(url, data=body, headers=headers)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy})
        ) if self.proxy else urllib.request.build_opener()
        with opener.open(request, timeout=self.timeout) as response:
            result = json.load(response)
            return (result, response.headers.get('Link', '')) if with_link else result
