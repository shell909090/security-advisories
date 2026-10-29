"""Early stop cuts pages; full reconciliation repairs deletions periodically."""
import datetime as dt
import unittest
from advisories.project_sync import collect_project, older_than
from advisories.sources.project import github_project
from advisories.http_client import Client
from advisories.collection_results import normalize_result
from advisories.sources import project
from unittest.mock import patch

NOW = dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc)
PRODUCT = {'id': 'x', 'repositories': ['o/r']}


class ProjectTests(unittest.TestCase):
    def test_early_stop_skips_next_page(self):
        client = Client()
        self.addCleanup(client.close)
        page = [{'ghsa_id': 'GHSA-new', 'updated_at': '2026-10-28T00:00:00Z'},
                {'ghsa_id': 'GHSA-old', 'updated_at': '2026-09-01T00:00:00Z'}]
        with patch.object(client, 'json', return_value=(page, '<https://api.github.com/next>; rel="next"')) as request:
            rows = list(github_project(client, PRODUCT, '2026-10-27T00:00:00Z'))
        self.assertEqual(len(rows), 1)
        self.assertEqual(request.call_count, 1)

    def test_unknown_date_not_early_stop(self):
        self.assertFalse(older_than({'published_at': '2020-01-01'}, NOW))
        self.assertFalse(older_than({'updated_at': None}, NOW))
        self.assertFalse(older_than({'updated_at': NOW.isoformat()}, NOW))

    def test_weekly_reconcile_and_failed_scan(self):
        old = {'full_checked_at': '2026-10-28T00:00:00Z', 'records': {'old': {}}}
        calls = []
        def fetch(client, product, since, until):
            calls.append(since)
            return []
        result = collect_project(fetch, None, PRODUCT, NOW, NOW, {'old': old})
        self.assertFalse(result['replace_records'])
        self.assertEqual(normalize_result(result, old, project)[2], {'old': {}})
        result = collect_project(fetch, None, PRODUCT, NOW, NOW + dt.timedelta(days=7), {'old': old})
        self.assertTrue(result['replace_records'])
        self.assertIsNone(calls[-1])
        self.assertEqual(normalize_result(result, old, project)[2], {})
        def fail(*args):
            raise RuntimeError('page failure')
        with self.assertRaises(RuntimeError):
            collect_project(fail, None, PRODUCT, NOW, NOW, {})
        self.assertEqual(old['records'], {'old': {}})

    def test_incremental_merge_matches_full_snapshot(self):
        client = Client()
        self.addCleanup(client.close)
        old_page = [{'ghsa_id': 'GHSA-old', 'updated_at': '2026-09-01T00:00:00Z'}]
        new_page = [{'ghsa_id': 'GHSA-new', 'updated_at': '2026-10-28T00:00:00Z'}] + old_page
        def fetch(page, since):
            with patch.object(client, 'json', return_value=(page, '')):
                return list(github_project(client, PRODUCT, since))
        old_rows = fetch(old_page, None)
        old = {'records': normalize_result({'records': old_rows}, {}, project)[2]}
        changed = fetch(new_page, '2026-10-27T00:00:00Z')
        merged = normalize_result({'records': changed}, old, project)[2]
        full = normalize_result({'records': fetch(new_page, None), 'replace_records': True}, {}, project)[2]
        self.assertEqual(merged, full)
