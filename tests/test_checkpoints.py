"""Scoped checkpoints and delayed CVE ingestion regressions."""
import unittest
from types import SimpleNamespace
from advisories.checkpoints import identity, window, cve_scope
from advisories.cve_index import retain_seen, inspected, mark_seen, cve_window, updated_coverage
from advisories.source_common import parse_time

NOW = parse_time('2026-10-29T12:00:00Z')
P = {'id': 'one', 'packages': [], 'repositories': [], 'keywords': ['one']}
Q = {'id': 'two', 'packages': [], 'repositories': [], 'keywords': ['two']}


def args():
    return SimpleNamespace(since=None, history=False, overlap_days=2, days=3)


class CheckpointTests(unittest.TestCase):
    def test_severity_and_other_products_do_not_change_product_identity(self):
        saved = {'checkpoint': '2026-10-28T12:00:00Z', 'collection_hash': identity('ghsa', P)}
        since, changed = window(args(), saved, identity('ghsa', P), NOW)
        self.assertFalse(changed)
        self.assertEqual(since, parse_time('2026-10-26T12:00:00Z'))
        changed_product = dict(P, packages=[{'ecosystem': 'npm', 'name': 'one'}])
        self.assertNotEqual(identity('ghsa', P), identity('ghsa', changed_product))
        self.assertEqual(identity('project', P), identity('project', changed_product))
        self.assertEqual(cve_scope([P, Q]), cve_scope([Q, P]))

    def test_cve_subset_reuses_independent_coverage(self):
        old = {'coverage': updated_coverage({}, [P, Q], parse_time('2026-10-28T12:00:00Z'))}
        self.assertEqual(cve_window(args(), old, [P], NOW), parse_time('2026-10-26T12:00:00Z'))
        new = dict(P, keywords=['new alias'])
        self.assertEqual(cve_window(args(), old, [new], NOW), parse_time('2026-10-26T12:00:00Z'))

    def test_old_modified_newly_ingested_keeps_inspection(self):
        entry = {'cveId': 'CVE-2020-1234', 'dateUpdated': '2020-01-01T00:00:00Z'}
        seen = {}
        mark_seen(seen, entry, {'one': 'hash'}, NOW)
        retained = retain_seen(seen, parse_time('2026-10-01'), NOW)
        self.assertTrue(inspected(retained, entry, {'one': 'hash'}))
        self.assertFalse(inspected(retained, entry, {'two': 'hash'}))
        mark_seen(retained, entry, {'two': 'hash'}, NOW)
        self.assertTrue(inspected(retained, entry, {'one': 'hash', 'two': 'hash'}))

    def test_changed_cve_does_not_keep_old_product_checks(self):
        seen = {}
        entry = {'cveId': 'CVE-2020-1234', 'dateUpdated': '2020-01-01T00:00:00Z'}
        mark_seen(seen, entry, {'one': 'hash'}, NOW)
        entry['dateUpdated'] = '2026-10-29T00:00:00Z'
        mark_seen(seen, entry, {'two': 'hash'}, NOW)
        self.assertFalse(inspected(seen, entry, {'one': 'hash'}))

    def test_legacy_cve_seen_refetched_once(self):
        self.assertEqual(retain_seen({'CVE-1': '2020-01-01'}, parse_time('2026-10-01'), NOW), {})

    def test_delayed_cve_is_not_downloaded_on_second_pass(self):
        from advisories.sources.cve import cve_delta
        from .test_fetch import FakeClient
        entry = {'cveId': 'CVE-2020-1234', 'dateUpdated': '2020-01-01T00:00:00Z'}
        log = [{'fetchTime': '2026-10-01T00:00:00Z', 'new': []},
               {'fetchTime': '2026-10-29T10:00:00Z', 'new': [entry]}]
        raw = {'cveMetadata': {'cveId': entry['cveId']}, 'containers': {}}
        client = FakeClient([log, raw])
        _, seen = cve_delta(client, [P], parse_time('2026-10-28'), NOW, {}, {}, 1)
        client = FakeClient([log])
        _, seen = cve_delta(client, [P], parse_time('2026-10-28'), NOW, seen, {}, 1)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(seen[entry['cveId']]['modified'], entry['dateUpdated'])
