"""Conditional responses retain bodies and pagination; failed refreshes cannot poison cache."""
import json
import unittest
from types import SimpleNamespace
from advisories.http_cache import HttpCache


def response(status=200, body=None, **headers):
    return SimpleNamespace(status_code=status, content=json.dumps(body).encode(), headers=headers)


class CacheTests(unittest.TestCase):
    def test_cold_warm_auth_and_link(self):
        cache = HttpCache()
        key, entry = cache.prepare('url', {'Authorization': 'token'}, None, 'project')
        cache.decode(response(body=[{'id': 1}], ETag='v1', Link='next'), key, entry, 'project')
        headers = {'Authorization': 'token'}
        next_key, entry = cache.prepare('url', headers, None, 'project')
        self.assertEqual(key, next_key)
        self.assertEqual(headers['If-None-Match'], 'v1')
        self.assertEqual(cache.decode(response(304), key, entry, 'project'), ([{'id': 1}], 'next'))
        other, _ = cache.prepare('url', {'Authorization': 'other'}, None, 'project')
        self.assertNotEqual(key, other)
        self.assertNotIn('token', json.dumps(cache.entries))

    def test_invalid_body_and_failure_rollback(self):
        cache = HttpCache()
        key, _ = cache.prepare('url', {}, None, 'project')
        cache.decode(response(body=[1], ETag='v1'), key, None, 'project')
        previous = cache.snapshot({}, set())
        malformed = SimpleNamespace(status_code=200, content=b'invalid', headers={'ETag': 'v2'})
        with self.assertRaises(ValueError):
            cache.decode(malformed, key, None, 'project')
        cache.decode(response(body=[2], ETag='v2'), key, None, 'project')
        self.assertEqual(cache.snapshot(previous, {'project'}), previous)
        with self.assertRaises(ValueError):
            cache.decode(response(304), None, None, 'project')

    def test_posts_and_unscoped_not_cached(self):
        cache = HttpCache()
        self.assertEqual(cache.prepare('url', {}, {}, 'project'), (None, None))
        self.assertEqual(cache.prepare('url', {}, None, 'osv'), (None, None))
