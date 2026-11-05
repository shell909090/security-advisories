"""Migration and SQLite commands preserve offline output and source isolation."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from advisories.migration import convert, progress_path
from advisories.storage import load_state, read_json
from .command_support import setup, catalog, command, record
from .test_update import module


class SQLiteCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        setup(self.root)
        catalog(self.root, [record(), record('GHSA-two', product='two')])
        self.source = self.root / 'state.json'
        self.destination = self.root / 'state.sqlite'

    def test_migration_retains_source_progress_and_outputs(self):
        before = self.source.read_bytes()
        progress_path(self.source).write_text('{"config_hash":"hash","records":[]}')
        code, _, _ = command(self.root, 'migrate-state', '--output', str(self.destination))
        self.assertEqual(code, 0)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(progress_path(self.source).read_bytes(), progress_path(self.destination).read_bytes())
        for args in [('summary', '--all'), ('summary', '--list', '--all'),
                     ('detail', '--product', 'one', '--history')]:
            expected = command(self.root, *args)
            actual = command(self.root, *args, '--state', str(self.destination))
            self.assertEqual(actual[:2], expected[:2])
        self.assertEqual(command(self.root, 'summary', '--state', str(self.destination))[0], 0)
        self.assertEqual(command(self.root, 'summary')[1], '')

    def test_existing_destination_and_failed_verification(self):
        self.destination.write_bytes(b'do not overwrite')
        with self.assertRaises(ValueError):
            convert(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), b'do not overwrite')
        self.destination.unlink()
        with patch('advisories.migration.integrity_check', side_effect=ValueError('bad')):
            with self.assertRaises(ValueError):
                convert(self.source, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertTrue(self.source.exists())

    def test_inline_http_cache_is_preserved(self):
        state = read_json(self.source, {})
        state['http_cache'] = {'key': {'source': 'cve', 'body': [1], 'used_at': 1}}
        self.source.write_text(json.dumps(state))
        convert(self.source, self.destination)
        self.assertEqual(load_state(self.destination, with_http=True), state)

    def test_update_failure_and_product_isolation(self):
        convert(self.source, self.destination)
        def collect(client, product, since, until, context):
            return {'records': [record(product=product['id'])], 'metadata': {}}
        args = ('update', '--state', str(self.destination), '--product', 'one')
        other = load_state(self.destination)['catalog']['two']
        with patch('advisories.update.discover', return_value={'mock': module(collect)}):
            self.assertEqual(command(self.root, *args)[0], 0)
        old = load_state(self.destination)
        self.assertEqual(old['catalog']['two'], other)
        def fail(*args):
            raise RuntimeError('offline')
        with patch('advisories.update.discover', return_value={'mock': module(fail)}):
            self.assertEqual(command(self.root, *args)[0], 1)
        new = load_state(self.destination)
        self.assertEqual(new['units'], old['units'])
        self.assertEqual(new['catalog']['two'], other)
