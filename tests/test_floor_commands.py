"""Floor filtering never consumes hidden history or changes offline detail."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from .command_support import setup, command, record, catalog


class FloorCommandTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        setup(self.root)
        catalog(self.root, [record(), record('GHSA-two', product='two')])

    def configure(self, value):
        path = self.root / 'products.json'
        products = json.loads(path.read_text())
        products[0]['min_version'] = value
        path.write_text(json.dumps(products))

    def test_history_and_detail_are_preserved(self):
        self.configure('2.0')
        state = (self.root / 'state.json').read_bytes()
        code, text, _ = command(self.root, 'summary')
        self.assertEqual(code, 0)
        self.assertNotIn('| ONE |', text)
        self.assertIn('| TWO |', text)
        self.assertNotIn('one:', (self.root / 'history.json').read_text())
        self.assertNotIn('| ONE |', command(self.root, 'summary', '--all')[1])
        self.assertIn('GHSA-test', command(self.root, 'detail', '--product', 'one',
                                         '--severity', 'critical')[1])
        self.assertEqual((self.root / 'state.json').read_bytes(), state)
        self.configure('1.0')
        self.assertIn('| ONE |', command(self.root, 'summary')[1])
        self.configure('2.0')
        self.assertNotIn('| ONE |', command(self.root, 'summary', '--shown')[1])

    def test_invalid_floor_only_errors_in_summary(self):
        self.configure('bad')
        self.assertEqual(command(self.root, 'summary')[0], 2)
        self.assertEqual(command(self.root, 'detail', '--product', 'one',
                                 '--severity', 'critical')[0], 0)

    def test_failed_output_does_not_remember_eligible_rows(self):
        self.configure('2')
        with patch('advisories.views.emit', side_effect=OSError('full')):
            self.assertEqual(command(self.root, 'summary')[0], 2)
        self.assertFalse((self.root / 'history.json').exists())

    def test_update_admission_ignores_floor(self):
        from advisories.update import refresh_catalog
        import datetime as dt
        state = {'version': 1, 'units': {'ghsa:one': {'records': {'GHSA-test': record()}}}}
        products = json.loads((self.root / 'products.json').read_text())
        products[0]['min_version'] = '999'
        refresh_catalog(state, products, 'high', [], dt.datetime.now(dt.timezone.utc))
        self.assertEqual(len(state['catalog']['one']['records']), 1)
