"""Batch pagination, precise product mapping and cached detail reuse."""
import copy
import unittest
from advisories.sources import osv, ghsa
from advisories.source_common import parse_time


def contexts(*names):
    return {name: {'product': {'id': name, 'packages': [{'ecosystem': 'PyPI', 'name': name}]},
                   'since': parse_time('2026-10-26')} for name in names}


class Client:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.hits = 0

    def json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response

    def cache_hit(self, count=1):
        self.hits += count


class OsvTests(unittest.TestCase):
    def test_shared_detail_then_only_index_on_second_run(self):
        entry = {'id': 'GHSA-one', 'modified': '2026-10-27T00:00:00Z'}
        index = {'results': [{'vulns': [entry]}, {'vulns': [entry]}]}
        client = Client([index, entry])
        results, cache = osv.collect_many(client, contexts('one', 'two'), None, {})
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(results['one']['records'][0]['products'], ['one'])
        self.assertEqual(results['two']['records'][0]['products'], ['two'])
        client = Client([index])
        _, again = osv.collect_many(client, contexts('one', 'two'), None, cache)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.hits, 1)
        self.assertEqual(cache, again)

    def test_timestamp_precision_does_not_refetch_unchanged_detail(self):
        index_time = '2026-10-15T14:55:34.900224Z'
        detail_time = '2026-10-15T14:55:34.900224098Z'
        record = {'id': 'GHSA-one', 'modified': detail_time}
        cache = {'details': {'GHSA-one': {'modified': detail_time, 'record': record}}}
        client = Client([{'results': [{'vulns': [{'id': 'GHSA-one', 'modified': index_time}]}]}])
        osv.collect_many(client, contexts('one'), None, cache)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.hits, 1)
        self.assertFalse(osv.same_modified(index_time, '2026-10-15T14:55:34.900225Z'))

    def test_changed_detail_and_failure_do_not_mutate_cache(self):
        old = {'id': 'GHSA-one', 'modified': 'a'}
        cache = {'details': {'GHSA-one': {'modified': 'a', 'record': old}}}
        snapshot = copy.deepcopy(cache)
        index = {'results': [{'vulns': [{'id': 'GHSA-one', 'modified': 'b'}]}]}
        client = Client([index, RuntimeError('network')])
        with self.assertRaisesRegex(RuntimeError, 'network'):
            osv.collect_many(client, contexts('one'), None, cache)
        self.assertEqual(cache, snapshot)
        client = Client([index, {'id': 'GHSA-one', 'modified': 'b', 'withdrawn': 'date'}])
        result, updated = osv.collect_many(client, contexts('one'), None, cache)
        self.assertTrue(result['one']['records'][0]['withdrawn'])
        self.assertEqual(updated['details']['GHSA-one']['modified'], 'b')

    def test_per_package_tokens_and_missing_index_validation(self):
        client = Client([{'results': [{'next_page_token': 'p'}, {}]}, {'results': [{}]}])
        osv.collect_many(client, contexts('one', 'two'), None, {})
        next_query = client.calls[1][1]['data']['queries']
        self.assertEqual(next_query, [{'package': {'ecosystem': 'PyPI', 'name': 'one'}, 'page_token': 'p'}])
        with self.assertRaisesRegex(ValueError, 'length mismatch'):
            osv.collect_many(Client([{'results': []}]), contexts('one'), None, {})

    def test_pagination_cycle_fails(self):
        page = {'results': [{'next_page_token': 'p'}]}
        with self.assertRaisesRegex(RuntimeError, 'pagination loop'):
            osv.collect_many(Client([page, page]), contexts('one'), None, {})

    def test_empty_snapshot_replaces_previous_product_records(self):
        result, _ = osv.collect_many(Client([{'results': [{}]}]), contexts('one'), None, {})
        self.assertTrue(result['one']['replace_records'])
        self.assertEqual(result['one']['records'], [])


class GhsaTests(unittest.TestCase):
    def test_batch_maps_only_affected_packages(self):
        class GitHub:
            def paginate_github(self, url, params):
                self.params = params
                return [{'ghsa_id': 'GHSA-one', 'vulnerabilities': [
                    {'package': {'ecosystem': 'pip', 'name': 'one'}}]}]
        client = GitHub()
        result, _ = ghsa.collect_many(client, contexts('one', 'two'), parse_time('2026-10-29'), {})
        self.assertEqual(client.params['affects'], 'one,two')
        self.assertEqual(result['one']['records'][0]['id'], 'GHSA-one')
        self.assertEqual(result['two']['records'], [])

    def test_different_windows_and_ecosystems_remain_separate(self):
        prepared = contexts('one', 'two', 'three')
        prepared['two']['since'] = parse_time('2026-10-20')
        prepared['three']['product']['packages'][0]['ecosystem'] = 'npm'
        self.assertEqual(len(ghsa.groups_for(prepared)), 3)

    def test_pypi_normalization(self):
        advisory = {'vulnerabilities': [{'package': {'ecosystem': 'pip', 'name': 'Some_Package'}}]}
        self.assertEqual(ghsa.mapped_products(advisory, 'pip', {'some-package': {'one'}}), {'one'})
