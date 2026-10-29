"""Known-ID refresh handles lost keywords and withdrawal without repeated downloads."""
import copy
import datetime as dt
import unittest
from advisories.nvd_review import review, batch_records
from advisories.sources.nvd import nvd_record
from advisories.source_common import stamp
from advisories.collection_results import normalize_result
from advisories.sources import nvd
from advisories.update import refresh_catalog

NOW = dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc)
PRODUCT = {'id': 'one', 'keywords': ['one'], 'packages': []}


def raw(ident, status='Analyzed', product='one'):
    return {'id': ident, 'vulnStatus': status, 'descriptions': [{'lang': 'en', 'value': 'updated'}],
            'configurations': [{'nodes': [{'cpeMatch': [
                {'criteria': f'cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*', 'vulnerable': True}]}]}],
            'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 8, 'baseSeverity': 'HIGH'}}]}}


class FakeClient:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = iter(responses) if responses is not None else None

    def json(self, url, params):
        self.calls.append(params)
        if self.responses is not None:
            result = next(self.responses)
            if isinstance(result, Exception):
                raise result
            return result
        ids = params['cveIds'].split(',')
        return {'totalResults': len(ids), 'vulnerabilities': [{'cve': raw(ident)} for ident in ids]}


class ReviewTests(unittest.TestCase):
    def test_batches_and_successful_discovery_not_repeated(self):
        old = {'records': {f'CVE-2026-{1000+i}': {} for i in range(202)}}
        rows = [nvd_record(raw('CVE-2026-1000'), PRODUCT)]
        client = FakeClient()
        result = review(client, PRODUCT, rows, old, NOW, nvd_record)
        self.assertEqual([len(c['cveIds'].split(',')) for c in client.calls], [100, 100, 1])
        self.assertTrue(all('keywordSearch' not in c and 'lastModStartDate' not in c for c in client.calls))
        saved = {**result['metadata'], 'records': {r['id']: r for r in result['records']}}
        client = FakeClient()
        review(client, PRODUCT, [], saved, NOW + dt.timedelta(days=6), nvd_record)
        self.assertEqual(client.calls, [])
        review(client, PRODUCT, [], saved, NOW + dt.timedelta(days=7), nvd_record)
        self.assertEqual(len(client.calls), 3)

    def test_missing_and_failure_preserve_old_state(self):
        old = {'records': {'CVE-2026-1000': {'description': 'old'}}}
        original = copy.deepcopy(old)
        for response in [{'totalResults': 0, 'vulnerabilities': []}, RuntimeError('offline')]:
            with self.subTest(response=response), self.assertRaises((ValueError, RuntimeError)):
                review(FakeClient([response]), PRODUCT, [], old, NOW, nvd_record)
            self.assertEqual(old, original)

    def test_pagination_and_wrong_id(self):
        entries = [{'cve': raw('CVE-2026-1000')}, {'cve': raw('CVE-2026-1001')}]
        client = FakeClient([{'totalResults': 2, 'vulnerabilities': [entry]} for entry in entries])
        self.assertEqual(len(batch_records(client, ['CVE-2026-1000', 'CVE-2026-1001'])), 2)
        self.assertEqual(client.calls[1]['startIndex'], 1)
        with self.assertRaises(ValueError):
            batch_records(FakeClient([{'totalResults': 1, 'vulnerabilities': entries[:1]}]), ['CVE-2026-9999'])

    def test_withdrawal_and_changed_product_leave_catalog(self):
        for replacement in [raw('CVE-2026-1000', 'Rejected'), raw('CVE-2026-1000', product='other')]:
            old = {'records': {'CVE-2026-1000': nvd_record(raw('CVE-2026-1000'), PRODUCT)}}
            client = FakeClient([{'totalResults': 1, 'vulnerabilities': [{'cve': replacement}]}])
            result = review(client, PRODUCT, [], old, NOW, nvd_record)
            records = normalize_result(result, old, nvd)[2]
            state = {'units': {'nvd:one': {'records': records}}}
            refresh_catalog(state, [PRODUCT], 'high', [], NOW)
            self.assertEqual(state['catalog']['one']['records'], [])
            self.assertIn('CVE-2026-1000', records)
            self.assertEqual(result['metadata']['known_checked_at']['CVE-2026-1000'], stamp(NOW))

    def test_failed_review_does_not_advance_persisted_checkpoint(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from .command_support import setup, command
        from advisories.http_client import Client
        ident = 'CVE-2026-1000'
        unit = {'checkpoint': '2026-10-01T00:00:00Z',
                'known_checked_at': {ident: '2026-10-01T00:00:00Z'},
                'records': {ident: nvd_record(raw(ident), PRODUCT)}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setup(root)
            path = root / 'state.json'
            path.write_text(json.dumps({'version': 1, 'units': {'nvd:one': unit}}))
            missing = {'totalResults': 0, 'vulnerabilities': []}
            with patch('advisories.update.discover', return_value={'nvd': nvd}):
                with patch.object(Client, 'json', return_value=missing):
                    self.assertEqual(command(root, 'update', '--product', 'one')[0], 1)
                state = json.loads(path.read_text())
                self.assertEqual(state['units']['nvd:one'], unit)
                self.assertEqual(len(state['catalog']['one']['records']), 1)
                self.assertTrue(state['catalog']['one']['errors'])
                def request(client, url, params=None, **kwargs):
                    if 'cveIds' in params:
                        return {'totalResults': 1, 'vulnerabilities': [{'cve': raw(ident, 'Rejected')}]}
                    return missing
                with patch.object(Client, 'json', request):
                    self.assertEqual(command(root, 'update', '--product', 'one')[0], 0)
                state = json.loads(path.read_text())
                self.assertNotEqual(state['units']['nvd:one']['checkpoint'], unit['checkpoint'])
                self.assertEqual(state['catalog']['one']['records'], [])
