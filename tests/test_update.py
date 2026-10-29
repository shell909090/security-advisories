import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from .command_support import setup, command, record


def module(collect):
    return SimpleNamespace(GLOBAL=False, collect=collect, MATCH_BASIS='exact-package')


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        setup(self.root)

    def collect(self, client, product, since, until, context):
        return {'records': [record('GHSA-' + product['id'], product['id'], 'high')], 'metadata': {}}

    def test_update_scope_threshold_and_history_isolation(self):
        history = self.root / 'history.json'
        history.write_text('do not read or write')
        with patch('advisories.update.discover', return_value={'mock': module(self.collect)}):
            self.assertEqual(command(self.root, 'update', '--product', 'one')[0], 0)
            state = json.loads((self.root / 'state.json').read_text())
            self.assertEqual(state['catalog']['one']['records'], [])
            self.assertNotIn('two', state['catalog'])
            self.assertEqual(command(self.root, 'update', '--product', 'two', '--min-severity', 'high')[0], 0)
            self.assertEqual(command(self.root, 'update', '--product', 'one', '--min-severity', 'high')[0], 0)
        state = json.loads((self.root / 'state.json').read_text())
        self.assertEqual(len(state['catalog']['one']['records']), 1)
        self.assertEqual(len(state['catalog']['two']['records']), 1)
        self.assertEqual(history.read_text(), 'do not read or write')

    def test_failure_preserves_checkpoint_and_catalog_warns(self):
        with patch('advisories.update.discover', return_value={'mock': module(self.collect)}):
            command(self.root, 'update', '--min-severity', 'high')
        old = json.loads((self.root / 'state.json').read_text())['units']['mock:one']['checkpoint']
        def fail(*args):
            raise RuntimeError('offline')
        with patch('advisories.update.discover', return_value={'mock': module(fail)}):
            self.assertEqual(command(self.root, 'update', '--min-severity', 'high')[0], 1)
        state = json.loads((self.root / 'state.json').read_text())
        self.assertEqual(state['units']['mock:one']['checkpoint'], old)
        code, text, errors = command(self.root, 'summary')
        self.assertEqual(code, 0)
        self.assertIn('| ONE |', text)
        self.assertIn('source failures', errors)

    def test_source_jobs_concurrent(self):
        barrier = threading.Barrier(2)
        def collect(*args):
            barrier.wait(timeout=2)
            return {'records': [], 'metadata': {}}
        with patch('advisories.update.discover', return_value={'mock': module(collect)}):
            self.assertEqual(command(self.root, 'update', '--jobs', '2')[0], 0)
