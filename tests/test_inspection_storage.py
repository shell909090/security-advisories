"""Scope references must preserve product/configuration isolation and resumability."""
import copy
import unittest
from advisories.inspection_storage import pack, unpack
from advisories.cve_index import inspected, mark_seen
from advisories.source_common import parse_time


class InspectionStorageTests(unittest.TestCase):
    def test_roundtrip_shares_scopes_and_does_not_mutate_input(self):
        scopes = {'one': 'a' * 64, 'two': 'b' * 64}
        data = {'seen': {str(i): {'modified': 'date', 'checked_at': 'now', 'products': dict(scopes)}
                         for i in range(10)}}
        before = copy.deepcopy(data)
        packed = pack(data, 'seen')
        self.assertEqual(len(packed['seen_scopes']), 1)
        self.assertNotIn('products', packed['seen']['0'])
        self.assertEqual(unpack(packed, 'seen'), data)
        self.assertEqual(data, before)
        self.assertEqual(len(pack({'seen': {}}, 'seen')['seen_scopes']), 0)

    def test_distinct_scopes_and_changed_cve_stay_independent(self):
        seen = {}
        now = parse_time('2026-10-29')
        first = {'cveId': 'CVE-1', 'dateUpdated': 'old'}
        second = dict(first, cveId='CVE-2')
        mark_seen(seen, first, {'one': 'hash'}, now)
        mark_seen(seen, second, {'one': 'hash'}, now)
        loaded = unpack(pack({'seen': seen}, 'seen'), 'seen')['seen']
        mark_seen(loaded, first, {'two': 'other'}, now)
        self.assertTrue(inspected(loaded, first, {'two': 'other'}))
        self.assertFalse(inspected(loaded, second, {'two': 'other'}))
        changed = dict(first, dateUpdated='new')
        mark_seen(loaded, changed, {'one': 'new-config'}, now)
        self.assertFalse(inspected(loaded, changed, {'one': 'hash'}))
        self.assertFalse(inspected(loaded, changed, {'two': 'other'}))
        self.assertEqual(len(pack({'seen': loaded}, 'seen')['seen_scopes']), 2)

    def test_legacy_and_invalid_reference(self):
        self.assertEqual(unpack({'seen': {'id': 'legacy'}}, 'seen'), {'seen': {'id': 'legacy'}})
        for reference in ('missing', 0, []):
            with self.assertRaises(ValueError):
                unpack({'seen': {'id': {'products_ref': reference}}, 'seen_scopes': {}}, 'seen')
        with self.assertRaises(ValueError):
            unpack({'seen': {'id': {'products_ref': '0'}}, 'seen_scopes': {'0': []}}, 'seen')

    def test_progress_and_state_refs_are_local(self):
        main = pack({'seen': {'a': {'products': {'one': 'old'}}}}, 'seen')
        progress = pack({'seen': {'b': {'products': {'one': 'new'}}}}, 'seen')
        loaded = {**unpack(main, 'seen')['seen'], **unpack(progress, 'seen')['seen']}
        self.assertEqual(loaded['a']['products'], {'one': 'old'})
        self.assertEqual(loaded['b']['products'], {'one': 'new'})
