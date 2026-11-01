"""KEV priority does not overwrite severity or duplicate summary counts."""
import copy
import datetime as dt
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from advisories import views
from advisories.evidence import priority
from advisories.records import merge_records
from advisories.selection import display_fingerprint, visible, remember
from advisories.sources.kev import record
from advisories.summary import render
from advisories.detail import render_row
from advisories.update import admitted


class KevPriorityTests(unittest.TestCase):
    def setUp(self):
        self.product = {'id': 'chrome', 'keywords': ['Chrome'], 'vendors': ['Google']}
        item = dict(cveID='CVE-2026-12345', dateAdded='2026-09-02',
                    vendorProject='Google', product='Chrome', vulnerabilityName='Example')
        self.evidence = record(item, self.product)
        self.row = merge_records({'kev:chrome': {'records': {'id': self.evidence}}})[0]

    def test_admission_and_exclusive_count(self):
        self.assertTrue(admitted(self.row, self.product, 'critical'))
        self.assertEqual(priority(self.row), 'critical')
        self.assertEqual(self.row['severity'], 'unknown')
        self.assertIn('| chrome | 1 | 0 | 0 |', render([(self.product, self.row)]))
        self.assertIn('按 Critical 优先级处理', '\n'.join(render_row(1, self.row)))
        withdrawn = copy.deepcopy(self.row)
        withdrawn['evidence'][0]['withdrawn'] = True
        self.assertEqual(priority(withdrawn), 'unknown')
        self.row['withdrawn'] = True
        self.assertFalse(admitted(self.row, self.product, 'critical'))

    def test_new_kev_reappears_then_deduplicates(self):
        before = copy.deepcopy(self.row)
        before['evidence'][0]['source'] = 'cve'
        before['severity'] = 'high'
        history = {'records': {}}
        remember(history, [(self.product, before)])
        self.assertNotEqual(display_fingerprint(before), display_fingerprint(self.row))
        now = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)
        args = SimpleNamespace(min_severity='critical', history=False, all=False, shown=False)
        cutoff = now - dt.timedelta(days=3)
        self.assertTrue(visible(args, self.product, self.row, history['records'], cutoff, now))
        remember(history, [(self.product, self.row)])
        self.assertFalse(visible(args, self.product, self.row, history['records'], cutoff, now))
        self.assertFalse(visible(args, self.product, self.row, {}, cutoff, now))

    def test_detail_selects_by_priority(self):
        args = SimpleNamespace(severity='critical', days=3, since=None, history=True,
                               product='chrome', output=None)
        with patch('advisories.views.catalog_rows', return_value=[(self.product, self.row)]):
            with patch('advisories.views.emit') as emit:
                views.detail(args)
                self.assertIn(self.row['id'], emit.call_args.args[0])
                args.severity = 'high'
                views.detail(args)
                self.assertNotIn(self.row['id'], emit.call_args.args[0])
