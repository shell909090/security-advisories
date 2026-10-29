import datetime as dt
import argparse
import contextlib
import io
import json
import tempfile
import threading
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import patch

from types import SimpleNamespace
from advisories.records import merge_records, meaningful
from advisories.source_common import parse_time, product_matches
from advisories.sources.cve import cve_delta
from advisories.sources.osv import osv_product
from advisories.http_client import Client
fetch = SimpleNamespace(merge_records=merge_records, meaningful=meaningful, parse_time=parse_time,
                        product_matches=product_matches, cve_delta=cve_delta, osv_product=osv_product, Client=Client)


def record(ident='GHSA-test', aliases=None, **extra):
    return dict(id=ident, aliases=aliases or [], products=['codex'], title='Sandbox bypass',
                description='May execute commands', severity='high', scores=[], affected=[],
                withdrawn=False, kind='vulnerability', **extra)


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def json(self, url, params=None, data=None):
        self.calls.append((url, data))
        return next(self.responses)


class FetchTests(unittest.TestCase):
    def test_transitive_aliases_merge(self):
        units = {str(i): {'records': {r['id']: r}} for i, r in enumerate([
            record('GHSA-a', ['CVE-2026-1234']), record('GO-1', ['GHSA-a']), record('CVE-2026-1234')])}
        merged = fetch.merge_records(units)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['id'], 'CVE-2026-1234')
        self.assertEqual(len(merged[0]['evidence']), 3)

    def test_clock_reference_changes_ignored_but_fix_changes_retained(self):
        a = record(published='old', modified='old', references=['https://old'])
        b = record(published='new', modified='new', references=['https://new'])
        self.assertEqual(fetch.meaningful(a), fetch.meaningful(b))
        b['affected'] = [{'fixed': '1.2.3'}]
        self.assertNotEqual(fetch.meaningful(a), fetch.meaningful(b))
        b = dict(a, withdrawn=True)
        self.assertNotEqual(fetch.meaningful(a), fetch.meaningful(b))

    def test_osv_pagination_retains_package_query(self):
        client = FakeClient([{'results': [{'vulns': [{'id': 'a', 'modified': 'm'}], 'next_page_token': 'next'}]},
                             {'results': [{'vulns': [{'id': 'b', 'modified': 'm'}]}]},
                             {'id': 'a', 'modified': 'm'}, {'id': 'b', 'modified': 'm'}])
        product = {'id': 'codex', 'packages': [{'ecosystem': 'npm', 'name': '@openai/codex'}]}
        self.assertEqual([r['id'] for r in fetch.osv_product(client, product)], ['a', 'b'])
        self.assertEqual(client.calls[1][1]['queries'][0]['package'], product['packages'][0])

    def test_cve_coverage_gap_fails(self):
        client = FakeClient([[{'fetchTime': '2026-10-20T00:00:00Z', 'new': [], 'updated': []}]])
        with self.assertRaisesRegex(RuntimeError, 'coverage gap'):
            fetch.cve_delta(client, [], fetch.parse_time('2026-10-01'), fetch.parse_time('2026-10-29'), {}, {}, 1)

    def test_cve_ingestion_time_and_rejected_record(self):
        entry = {'cveId': 'CVE-2026-1234', 'dateUpdated': '2026-10-01T00:00:00Z'}
        batches = [{'fetchTime': '2026-10-28T00:00:00Z', 'new': [entry], 'updated': []},
                   {'fetchTime': '2026-10-01T00:00:00Z', 'new': [], 'updated': []}]
        raw = {'cveMetadata': {'cveId': entry['cveId'], 'state': 'REJECTED'}, 'containers': {}}
        client = FakeClient([batches, raw])
        previous = {entry['cveId']: {'products': ['codex']}}
        rows, seen = fetch.cve_delta(client, [], fetch.parse_time('2026-10-27'), fetch.parse_time('2026-10-29'), {}, previous, 1)
        self.assertTrue(rows[0]['withdrawn'])
        self.assertEqual(seen[entry['cveId']]['modified'], entry['dateUpdated'])

    def test_matching_no_substring_accident(self):
        products = [{'id': 'hermes', 'keywords': ['Hermes Agent'], 'repositories': ['NousResearch/hermes-agent'], 'packages': []}]
        self.assertEqual(fetch.product_matches({'description': 'hermes agentic random tool'}, products), [])
        self.assertEqual(fetch.product_matches({'description': 'Hermes Agent vulnerability'}, products), ['hermes'])
        raw = {'containers': {'cna': {'affected': [{'product': 'Firefox'}],
                                     'credits': [{'value': 'Hermes Agent'}]}}}
        self.assertEqual(fetch.product_matches(raw, products), [])

    def test_github_cursor_links(self):
        client = fetch.Client()
        next_url = 'https://api.github.com/advisories?after=cursor'
        with patch.object(client, 'json', side_effect=[([{'id': 1}], '<'+next_url+'>; rel="next"'), ([{'id': 2}], '')]) as get:
            self.assertEqual(list(client.paginate_github('https://api.github.com/advisories')), [{'id': 1}, {'id': 2}])
            self.assertEqual(get.call_args_list[1].args, (next_url, None))

    def test_withdrawn_duplicate_not_rejected_cve(self):
        a = record('GHSA-a', ['CVE-2026-1234'])
        a['withdrawn'] = True
        b = record('CVE-2026-1234')
        groups = fetch.merge_records({'ghsa:x': {'records': {'a': a}}, 'nvd:x': {'records': {'b': b}}})
        self.assertFalse(groups[0]['withdrawn'])
        self.assertTrue(groups[0]['withdrawal_conflict'])


if __name__ == '__main__':
    unittest.main()
