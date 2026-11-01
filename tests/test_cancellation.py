"""Interrupts cancel queued work and persist only completed source units."""
import json
import tempfile
import threading
import unittest
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import patch
from advisories.http_client import Client
from advisories.scheduling import wait_ready
from .command_support import setup, command


class CancellationTests(unittest.TestCase):
    def test_wait_interrupt_cancels_before_shutdown(self):
        future = Future()
        cancelled = threading.Event()
        with patch('advisories.scheduling.wait', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                wait_ready({future: ('kev', ('kev', None, 'kev', {}))}, cancelled.set)
        self.assertTrue(cancelled.is_set())
        self.assertTrue(future.cancelled())

    def test_cancel_wakes_cooldown_and_stops_requests(self):
        client = Client()
        self.addCleanup(client.close)
        client.cancel()
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            client.cooldowns.pause(3600)
        with patch.object(client, 'open_json') as request:
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                client.json('https://example.com')
            request.assert_not_called()

    def test_interrupt_persists_completed_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            setup(root)
            def interrupted(args, jobs, collect, state, completed, errors, cancel):
                state['units']['kev:one'] = {'checkpoint': '2026-11-02T00:00:00Z', 'records': {}}
                completed.append({'source': 'kev', 'seconds': 1})
                raise KeyboardInterrupt
            with patch('advisories.update.execute_jobs', side_effect=interrupted):
                code, _, _ = command(root, 'update', '--sources', 'kev,nvd')
            self.assertEqual(code, 130)
            state = json.loads((root / 'state.json').read_text())
            self.assertIn('kev:one', state['units'])
            self.assertNotIn('nvd:one', state['units'])
            self.assertTrue(state['last_update']['errors'])
            self.assertFalse((root / 'history.json').exists())
