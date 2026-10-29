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

import fetch


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
        client = FakeClient([{'vulns': [{'id': 'a'}], 'next_page_token': 'next'}, {'vulns': [{'id': 'b'}]}])
        product = {'id': 'codex', 'packages': [{'ecosystem': 'npm', 'name': '@openai/codex'}]}
        self.assertEqual([r['id'] for r in fetch.osv_product(client, product)], ['a', 'b'])
        self.assertEqual(client.calls[1][1]['package'], product['packages'][0])

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
        self.assertEqual(seen[entry['cveId']], entry['dateUpdated'])

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

    def test_partial_failure_preserves_checkpoint_and_repeated_output_is_empty(self):
        with tempfile.TemporaryDirectory(dir=fetch.ROOT) as directory:
            root = Path(directory)
            products = [{'id': 'codex', 'packages': [{'ecosystem': 'npm', 'name': '@openai/codex'}]}]
            (root/'products.json').write_text(json.dumps(products))
            old = {'version': 1, 'units': {'ghsa:codex': {'checkpoint': '2026-01-01T00:00:00Z', 'records': {}}}, 'seen_output': {}}
            (root/'state.json').write_text(json.dumps(old))
            args = argparse.Namespace(products=root/'products.json', state=root/'state.json', output=root/'report.json',
                                      sources='ghsa,osv', since=None, overlap_days=2, days=3, workers=1,
                                      timeout=1, proxy=None, min_severity='high', all=False)
            with patch('sources.ghsa.collect', side_effect=RuntimeError('offline')), patch('sources.osv.collect', return_value={'records':[record(published=fetch.stamp(dt.datetime.now(fetch.UTC)))], 'metadata':{}}), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fetch.run(args), 1)
                state = json.loads(args.state.read_text())
                self.assertEqual(state['units']['ghsa:codex']['checkpoint'], '2026-01-01T00:00:00Z')
                self.assertEqual(len(json.loads(args.output.read_text())['changes']), 1)
                self.assertEqual(fetch.run(args), 1)
                self.assertEqual(json.loads(args.output.read_text())['changes'], [])

    def test_discovered_sources_run_concurrently_and_disabled_history_untouched(self):
        with tempfile.TemporaryDirectory(dir=fetch.ROOT) as directory:
            root = Path(directory)
            products = [{'id':'codex','packages':[{'ecosystem':'npm','name':'@openai/codex'}]}]
            (root/'products.json').write_text(json.dumps(products))
            (root/'history.json').write_text('not valid JSON: must not be read')
            barrier = threading.Barrier(2)
            def collect(client, product, since, until, context):
                barrier.wait(timeout=2) # Sequential scheduling would fail this source.
                return {'records': [], 'metadata': {}}
            modules = {name: SimpleNamespace(GLOBAL=False,collect=collect) for name in ('new_a','new_b')}
            args = argparse.Namespace(products=root/'products.json',state=root/'state.json',output=root/'report.json',
                dedup_history=root/'history.json',sources=None,since=None,days=3,overlap_days=2,workers=1,jobs=2,
                timeout=1,proxy=None,min_severity='critical',all=False,skip_dedup_filter=True)
            with patch('sources.discover', return_value=modules), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fetch.run(args), 0)
            self.assertEqual((root/'history.json').read_text(),'not valid JSON: must not be read')
            self.assertEqual(set(json.loads((root/'state.json').read_text())['units']), {'new_a:codex','new_b:codex'})


if __name__ == '__main__':
    unittest.main()
