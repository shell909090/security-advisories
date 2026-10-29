"""Archives accelerate matching versions only; incomplete coverage always falls back."""
import datetime as dt
import io
import json
import unittest
import zipfile
from advisories.cve_bundle import choose_asset, load_bundle, read_records, PREFIX

NOW = dt.datetime(2026, 10, 29, 14, tzinfo=dt.timezone.utc)
DATE = '2026-10-29T10:00:00Z'


def zipped(records):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for ident, modified in records:
            archive.writestr('deltaCves/' + ident + '.json',
                             json.dumps({'cveMetadata': {'cveId': ident, 'dateUpdated': modified}}))
    return output.getvalue()


class BundleTests(unittest.TestCase):
    def test_exact_version_and_missing_records(self):
        pending = [{'cveId': 'CVE-2026-1000', 'dateUpdated': DATE},
                   {'cveId': 'CVE-2026-1001', 'dateUpdated': DATE}]
        content = zipped([('CVE-2026-1000', DATE), ('CVE-2026-1001', '2026-10-28T10:00:00Z')])
        self.assertEqual(list(read_records(content, pending)), ['CVE-2026-1000'])

    def test_asset_cost_and_date_gate(self):
        asset = {'name': '2026-10-29_delta_CVEs_at_1300Z.zip', 'size': 100000,
                 'browser_download_url': PREFIX + 'tag/file.zip'}
        self.assertEqual(choose_asset({'assets': [asset]}, 200, NOW), asset)
        self.assertIsNone(choose_asset({'assets': [dict(asset, size=10000000)]}, 200, NOW))
        self.assertIsNone(choose_asset({'assets': [asset]}, 200, NOW - dt.timedelta(days=1)))

    def test_failure_is_fallback_and_small_runs_skip_discovery(self):
        class Client:
            calls = 0
            def json(self, url):
                self.calls += 1
                raise RuntimeError('offline')
            def bytes(self, url):
                raise AssertionError('not reached')
        client = Client()
        self.assertEqual(load_bundle(client, [], NOW), {})
        self.assertEqual(client.calls, 0)
        pending = [{'cveId': 'CVE-2026-' + str(1000 + i), 'dateUpdated': DATE} for i in range(200)]
        self.assertEqual(load_bundle(client, pending, NOW), {})
        self.assertEqual(client.calls, 1)

    def test_collection_falls_back_for_missing_archive_ids(self):
        from unittest.mock import patch
        from advisories.sources.cve import cve_delta
        from .test_fetch import FakeClient
        entries = [{'cveId': f'CVE-2026-{number}', 'dateUpdated': DATE} for number in (1000, 1001)]
        raw = [{'cveMetadata': {'cveId': entry['cveId']}, 'containers': {}} for entry in entries]
        log = [{'fetchTime': '2026-10-01T00:00:00Z', 'new': []},
               {'fetchTime': DATE, 'new': entries}]
        client = FakeClient([log, raw[1]])
        with patch('advisories.sources.cve.load_bundle', return_value={entries[0]['cveId']: raw[0]}):
            _, seen = cve_delta(client, [], NOW - dt.timedelta(days=1), NOW, {}, {}, 1)
        self.assertEqual(set(seen), {entry['cveId'] for entry in entries})
        self.assertEqual(len(client.calls), 2)
