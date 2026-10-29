"""Regression coverage for interrupted CVE batches and HTTP keep-alive."""
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from advisories.http_client import Client
from advisories.progress import CveProgress
from advisories.sources.cve import download_batches


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.server.peers.append(self.client_address)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ProgressTests(unittest.TestCase):
    def test_connection_reused(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.peers = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = Client(timeout=2)
        try:
            url = f'http://127.0.0.1:{server.server_port}/'
            self.assertEqual(client.json(url), {'ok': True})
            self.assertEqual(client.json(url), {'ok': True})
            self.assertEqual(server.peers[0], server.peers[1])
        finally:
            client.close()
            server.shutdown()
            server.server_close()
            thread.join()

    def test_failed_batch_saved_and_config_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            state.write_text('{"checkpoint": "unchanged"}')
            progress = CveProgress(state, 'config-a')
            def fetch(entry):
                if entry == 101:
                    raise RuntimeError('failed detail')
                return {'cveId': str(entry), 'dateUpdated': 'date'}, {'id': str(entry)}
            with self.assertRaisesRegex(RuntimeError, 'failed detail'):
                download_batches(fetch, list(range(103)), 2, [], {}, progress)
            saved = progress.load()
            self.assertEqual(len(saved['seen']), 102)
            self.assertNotIn('101', saved['seen'])
            self.assertEqual(len(saved['records']), 102)
            self.assertEqual(json.loads(state.read_text())['checkpoint'], 'unchanged')
            self.assertEqual(CveProgress(state, 'config-b').load(), {})
            pending = [i for i in range(103) if str(i) not in saved['seen']]
            self.assertEqual(pending, [101])
            progress.clear()
            self.assertEqual(progress.load(), {})
