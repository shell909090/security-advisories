"""Skipped NVD jobs do not fetch, change evidence or consume checkpoints/history."""
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from advisories.checkpoints import identity
from advisories.storage import save_state, load_state
from .command_support import setup, command
from .test_update import module


class NVDSamplingCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        setup(self.root)
        self.path = self.root / 'state.sqlite'
        self.products = json.loads((self.root / 'products.json').read_text())
        now = dt.datetime.now(dt.timezone.utc)
        units = {'nvd:' + p['id']: {'checkpoint': (now - dt.timedelta(days=i * 4)).isoformat(),
                 'collection_hash': identity('nvd', p), 'records': {}, 'known_checked_at': {}}
                 for i, p in enumerate(self.products)}
        self.state = {'version': 1, 'units': units}
        save_state(self.path, self.state)
        (self.root / 'history.json').write_text('untouched')
        self.collect = Mock(return_value={'records': [], 'metadata': {'known_checked_at': {}}})
        self.sources = {'nvd': module(self.collect)}

    def update(self, *args):
        with patch('advisories.update.discover', return_value=self.sources):
            with patch('advisories.http_client.Client.json', side_effect=AssertionError('no network')):
                return command(self.root, 'update', '--state', str(self.path), *args)

    def test_recent_empty_result_skipped_stale_product_refreshed(self):
        code, _, logs = self.update()
        self.assertEqual(code, 0)
        self.assertIn('NVD plan: 1 selected, 1 skipped', logs)
        self.assertEqual(self.collect.call_count, 1)
        self.assertEqual(self.collect.call_args.args[1]['id'], 'two')
        new = load_state(self.path)
        self.assertEqual(new['units']['nvd:one'], self.state['units']['nvd:one'])
        self.assertNotEqual(new['units']['nvd:two']['checkpoint'], self.state['units']['nvd:two']['checkpoint'])
        self.assertEqual((self.root / 'history.json').read_text(), 'untouched')

    def test_full_refresh_respects_selected_product(self):
        self.assertEqual(self.update('--nvd-full', '--product', 'one')[0], 0)
        self.assertEqual(self.collect.call_count, 1)
        self.assertEqual(self.collect.call_args.args[1]['id'], 'one')
        self.assertEqual(load_state(self.path)['units']['nvd:two'], self.state['units']['nvd:two'])

    def test_failed_refresh_preserves_checkpoint(self):
        self.collect.side_effect = RuntimeError('offline')
        self.assertEqual(self.update()[0], 1)
        self.assertEqual(load_state(self.path)['units'], self.state['units'])

    def test_later_forced_refresh_keeps_original_overlap_window(self):
        self.assertEqual(self.update()[0], 0)
        self.assertEqual(self.collect.call_args.args[1]['id'], 'two')
        self.collect.reset_mock()
        self.assertEqual(self.update('--product', 'one', '--nvd-full')[0], 0)
        expected = dt.datetime.fromisoformat(self.state['units']['nvd:one']['checkpoint']) - dt.timedelta(days=2)
        self.assertEqual(self.collect.call_args.args[2], expected)
