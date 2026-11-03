import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from .command_support import setup, command, record, catalog


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        setup(self.root)

    def test_summary_twice_and_detail_all_exact_level(self):
        catalog(self.root, [record(), record('GHSA-high', severity='high'),
                            record('GHSA-old', date='2020-01-01T00:00:00Z')])
        code, text, _ = command(self.root, 'summary')
        self.assertEqual(code, 0)
        self.assertIn('| ONE | 0 | 1 | 1 |', text)
        self.assertNotIn('总数', text)
        self.assertEqual(len(text.splitlines()[-1].split('|')), 9)
        self.assertIn('2.0', text)
        self.assertNotIn('GHSA-', text)
        self.assertEqual(command(self.root, 'summary')[1], '')
        history = (self.root / 'history.json').read_bytes()
        code, text, _ = command(self.root, 'detail', '--product', 'one', '--severity', 'critical')
        self.assertEqual(code, 0)
        self.assertNotIn('GHSA-old', text)
        full = command(self.root, 'detail', '--product', 'one', '--severity', 'critical', '--history')[1]
        self.assertIn('GHSA-old', full)
        self.assertIn('GHSA-test', text)
        self.assertNotIn('GHSA-high', text)
        self.assertEqual((self.root / 'history.json').read_bytes(), history)

    def test_detail_default_levels_and_concise_output(self):
        catalog(self.root, [record(), record('GHSA-high', severity='high'),
                            record('GHSA-low', severity='low')])
        code, text, _ = command(self.root, 'detail', '--product', 'one')
        self.assertEqual(code, 0)
        self.assertIn('GHSA-test', text)
        self.assertIn('GHSA-high', text)
        self.assertNotIn('GHSA-low', text)
        self.assertIn('远程代码执行', text)
        self.assertNotIn('评分', text)
        self.assertNotIn('原始证据', text)

    def test_filtered_records_not_marked_and_read_modes(self):
        catalog(self.root, [record(), record('GHSA-two', product='two'), record('GHSA-high', severity='high')])
        command(self.root, 'summary', '--product', 'one', '--min-severity', 'critical')
        saved = (self.root / 'history.json').read_bytes()
        self.assertNotIn('GHSA-high', saved.decode())
        self.assertNotIn('two:', saved.decode())
        self.assertIn('| ONE |', command(self.root, 'summary', '--shown')[1])
        self.assertIn('| TWO |', command(self.root, 'summary', '--all')[1])
        self.assertEqual((self.root / 'history.json').read_bytes(), saved)
        self.assertIn('| TWO |', command(self.root, 'summary')[1])
        self.assertEqual(command(self.root, 'summary')[1], '')

    def test_output_failure_does_not_consume_history(self):
        catalog(self.root, [record()])
        with patch('advisories.views.emit', side_effect=OSError('disk full')):
            self.assertEqual(command(self.root, 'summary')[0], 2)
        self.assertFalse((self.root / 'history.json').exists())
        self.assertIn('| ONE |', command(self.root, 'summary')[1])

    def test_alias_migration_ignored_but_content_changes_reported(self):
        item = record()
        catalog(self.root, [item])
        command(self.root, 'summary')
        item['aliases'] = ['CVE-2026-12345']
        catalog(self.root, [item])
        self.assertEqual(command(self.root, 'summary')[1], '')
        item['description'] += ' The fixed version is 3.0.'
        item['published'] = item['modified'] = '2020-01-01T00:00:00Z'
        catalog(self.root, [item])
        self.assertIn('| ONE |', command(self.root, 'summary')[1])

    def test_legacy_cache_requires_update(self):
        (self.root / 'state.json').write_text('{"version":1,"units":{}}')
        self.assertEqual(command(self.root, 'summary')[0], 2)

    def test_detail_unknown_product_fails(self):
        catalog(self.root, [])
        self.assertEqual(command(self.root, 'detail', '--product', 'missing', '--severity', 'high')[0], 2)

    def test_null_dates_do_not_break_summary(self):
        row = record()
        row['published'] = row['modified'] = None
        catalog(self.root, [row])
        self.assertEqual(command(self.root, 'summary')[:2], (0, ''))
        self.assertIn('| ONE |', command(self.root, 'summary', '--history')[1])

    def test_update_defaults_to_high(self):
        from advisories.cli import build_parser
        self.assertEqual(build_parser().parse_args(['update']).min_severity, 'high')
