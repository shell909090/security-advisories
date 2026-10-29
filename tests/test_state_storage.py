"""Compressed sidecar migration and interrupted writes must not lose checkpoints."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from advisories.cache_storage import cache_path, save_cache
from advisories.storage import atomic_json, load_state, save_state
from advisories.http_cache import HttpCache
from advisories.cli import build_parser
from advisories.validation import validate
from .test_http_cache import response


class StateStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.json'
        cache = HttpCache()
        key, entry = cache.prepare('url', {}, None, 'project')
        cache.decode(response(body=[1], ETag='v1', Link='next'), key, entry, 'project')
        self.state = {'version': 1, 'units': {'cve': {'checkpoint': 'old', 'cve_seen': {
            'CVE-1': {'modified': 'date', 'checked_at': 'now', 'products': {'one': 'hash'}}}}},
            'http_cache': cache.snapshot({}, set()), 'catalog': {}}

    def test_inline_migration_and_304_body_link_survive(self):
        atomic_json(self.path, self.state)
        cache_path(self.path).write_bytes(b'ignored stale sidecar')
        self.assertEqual(load_state(self.path, with_http=True), self.state)
        save_state(self.path, load_state(self.path, with_http=True))
        raw = json.loads(self.path.read_text())
        self.assertNotIn('http_cache', raw)
        self.assertIn('cve_seen_scopes', raw['units']['cve'])
        self.assertEqual(load_state(self.path, with_http=True), self.state)
        with patch('advisories.storage.load_cache', side_effect=AssertionError('offline read')):
            self.assertNotIn('http_cache', load_state(self.path))
        cache = HttpCache(load_state(self.path, with_http=True)['http_cache'])
        headers = {}
        key, entry = cache.prepare('url', headers, None, 'project')
        self.assertEqual(headers['If-None-Match'], 'v1')
        self.assertEqual(cache.decode(response(304), key, entry, 'project'), ([1], 'next'))

    def test_missing_and_damaged_cache_preserve_business_state(self):
        save_state(self.path, self.state)
        cache_path(self.path).unlink()
        self.assertEqual(load_state(self.path, with_http=True)['http_cache'], {})
        for content in (b'broken', bytes.fromhex('1f8b080000000000000307'), gzip.compress(b'{"version":9,"entries":{}}'),
                        gzip.compress(b'{"version":1,"entries":{"bad":{}}}')):
            cache_path(self.path).write_bytes(content)
            with self.assertLogs('advisories.cache_storage', level='WARNING'):
                loaded = load_state(self.path, with_http=True)
            self.assertEqual(loaded['http_cache'], {})
            self.assertEqual(loaded['units'], self.state['units'])

    def test_cache_write_failure_leaves_original_state(self):
        atomic_json(self.path, self.state)
        before = self.path.read_bytes()
        with patch('advisories.storage.save_cache', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                save_state(self.path, self.state)
        self.assertEqual(self.path.read_bytes(), before)

    def test_state_failure_after_cache_write_keeps_old_checkpoint(self):
        save_state(self.path, self.state)
        before = self.path.read_bytes()
        changed = load_state(self.path, with_http=True)
        changed['units']['cve']['checkpoint'] = 'new'
        changed['http_cache'] = {}
        with patch('advisories.storage.atomic_json', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                save_state(self.path, changed)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(load_state(self.path)['units']['cve']['checkpoint'], 'old')

    def test_compression_and_output_collision(self):
        save_cache(self.path, {'large': {'source': 'cve', 'body': ['repeated data'] * 10000, 'used_at': 1}})
        self.assertLess(cache_path(self.path).stat().st_size, 5000)
        parser = build_parser()
        args = parser.parse_args(['summary', '--state', str(self.path), '--output', str(cache_path(self.path))])
        with self.assertRaises(SystemExit), patch('sys.stderr'):
            validate(parser, args)

    def test_short_filename_and_legacy_fallback(self):
        self.assertEqual(cache_path(self.path).name, 'http-cache.json.gz')
        save_state(self.path, self.state)
        legacy = Path(str(self.path) + '.http-cache.json.gz')
        cache_path(self.path).rename(legacy)
        self.assertEqual(load_state(self.path, with_http=True), self.state)
        save_state(self.path, self.state)
        self.assertTrue(cache_path(self.path).exists())
        legacy.write_bytes(b'old file is no longer read')
        self.assertEqual(load_state(self.path, with_http=True), self.state)
