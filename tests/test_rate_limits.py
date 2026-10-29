"""Cooldown headers and service isolation; no real waiting or network."""
import unittest
import urllib.error
from unittest.mock import patch
from advisories.rate_limits import Cooldowns, delay, limited, retry_after
from advisories.http_client import Client


def error(status, headers, reason='HTTP error'):
    return urllib.error.HTTPError('https://api.github.com/x', status, reason, headers, None)


class RateLimitTests(unittest.TestCase):
    def test_header_precedence_and_dates(self):
        with patch('advisories.rate_limits.time.time', return_value=100):
            self.assertEqual(delay(error(429, {'Retry-After': '12'}), 0), 12)
            self.assertEqual(delay(error(403, {'X-RateLimit-Remaining': '0',
                                               'X-RateLimit-Reset': '130'}), 0), 31)
            self.assertEqual(delay(error(429, {}), 1), 120)
        self.assertEqual(retry_after('Thu, 01 Jan 1970 00:02:00 GMT', 100), 20)
        self.assertFalse(limited(error(403, {})))
        self.assertTrue(limited(error(403, {}, 'secondary rate limit')))

    def test_host_isolation_and_persistent_cooldown(self):
        cooldowns = Cooldowns()
        with patch('advisories.rate_limits.time.monotonic', return_value=10):
            cooldowns.defer('api.github.com', 30)
            with patch('advisories.rate_limits.time.sleep') as sleep:
                cooldowns.wait('api.osv.dev')
                sleep.assert_not_called()
                cooldowns.wait('api.github.com')
                sleep.assert_called_once_with(30)

    def test_403_retry_only_for_limits(self):
        client = Client()
        self.addCleanup(client.close)
        with patch.object(client, 'open_json', side_effect=[error(403, {'Retry-After': '0'}), {}]):
            self.assertEqual(client.json('https://api.github.com/x'), {})
        with patch.object(client, 'open_json', side_effect=error(403, {})) as request:
            with self.assertRaises(RuntimeError):
                client.json('https://api.github.com/x')
            self.assertEqual(request.call_count, 1)
