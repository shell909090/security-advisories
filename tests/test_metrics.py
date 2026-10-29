"""Verify source attribution, body byte semantics and retry accounting."""
import gzip
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from advisories.http_client import Client


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.server.count += 1
        status = 503 if self.server.count == 1 else 200
        content = gzip.compress(b'{"ok": true}')
        self.send_response(status)
        self.send_header('Content-Encoding', 'gzip')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *args):
        pass


class MetricTests(unittest.TestCase):
    def test_decoded_bytes_retry_and_source(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.count = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = Client(timeout=2)
        try:
            scoped = client.for_source('osv')
            with patch('advisories.http_client.time.sleep'):
                self.assertEqual(scoped.json(f'http://127.0.0.1:{server.server_port}/'), {'ok': True})
            scoped.cache_hit()
            stats = client.metrics.snapshot()['osv']
            self.assertEqual(stats['requests'], 2)
            self.assertEqual(stats['response_bytes'], 24)
            self.assertEqual(stats['retries'], 1)
            self.assertEqual(stats['http_errors'], 1)
            self.assertEqual(stats['cache_hits'], 1)
        finally:
            client.close()
            server.shutdown()
            server.server_close()
            thread.join()
