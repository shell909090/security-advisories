"""Conservative floor boundaries and source/product isolation."""
import unittest
from advisories.version_floor import excluded, minimum
from advisories.checkpoints import identity
from .test_version_scope import PRODUCT, row, gh


class FloorTests(unittest.TestCase):
    def setUp(self):
        self.product = dict(PRODUCT, min_version='2.0')

    def test_numeric_boundaries_and_reintroductions(self):
        for span, hidden in [('< 2', True), ('<= 2', False), ('< 1.9', True),
                             ('>= 3, < 4', False), ('< 1 || >= 3, < 4', False),
                             ('>= 1, < 2.0.0', True), ('< 2.0rc1', False),
                             ('>= 3, < 2', False), ('*', False)]:
            with self.subTest(span=span):
                node = gh('one_pkg', 'pip', '99')
                node['vulnerable_version_range'] = span
                self.assertEqual(excluded(row([node]), self.product), hidden)

    def test_missing_and_conflicting_evidence(self):
        safe = row([gh('one_pkg', 'pip', '2')])
        self.assertTrue(excluded(safe, self.product))
        safe['evidence'].append({'affected': []})
        self.assertFalse(excluded(safe, self.product))
        safe['evidence'][-1]['withdrawn'] = True
        self.assertTrue(excluded(safe, self.product))
        self.assertFalse(excluded(row([gh('other', 'pip', '1')]), self.product))
        self.assertFalse(excluded(row([]), self.product))
        self.assertFalse(excluded(row([gh('one_pkg', 'pip', '2')]), PRODUCT))

    def test_osv_events_versions_and_unknown_types(self):
        node = {'package': {'name': 'one_pkg', 'ecosystem': 'PyPI'}, 'ranges': [
            {'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '2'}]}]}
        self.assertTrue(excluded(row([node]), self.product))
        node['versions'] = ['3.0']
        self.assertFalse(excluded(row([node]), self.product))
        node['versions'] = []
        node['ranges'][0]['events'].append({'introduced': '3'})
        self.assertFalse(excluded(row([node]), self.product))
        node['ranges'][0]['type'] = 'GIT'
        self.assertFalse(excluded(row([node]), self.product))

    def test_cve_changes_default_and_inclusive_boundary(self):
        entry = {'version': '0', 'lessThan': '2', 'status': 'affected'}
        node = {'product': 'one', 'versions': [entry]}
        self.assertTrue(excluded(row([node]), self.product))
        node['defaultStatus'] = 'affected'
        self.assertFalse(excluded(row([node]), self.product))
        node.pop('defaultStatus')
        entry['changes'] = [{'at': '1', 'status': 'unaffected'}]
        self.assertFalse(excluded(row([node]), self.product))
        entry.pop('changes')
        entry['lessThanOrEqual'] = entry.pop('lessThan')
        self.assertFalse(excluded(row([node]), self.product))

    def test_nvd_and_multiple_packages(self):
        node = {'vulnerable': True, 'criteria': 'cpe:2.3:a:vendor:one:*:*:*:*:*:*:*:*',
                'versionEndExcluding': '2'}
        self.assertTrue(excluded(row([{'nodes': [{'cpeMatch': [node]}]}]), self.product))
        node['versionEndIncluding'] = node.pop('versionEndExcluding')
        self.assertFalse(excluded(row([node]), self.product))
        nodes = [gh('one_pkg', 'pip', '2'), gh('one_pkg', 'pip', '3')]
        self.assertFalse(excluded(row(nodes), self.product))

    def test_validation_and_collection_identity(self):
        for value in ('', 'v2.0', '2rc1', 2, [], True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                minimum(dict(PRODUCT, min_version=value))
        self.assertIsNone(minimum(dict(PRODUCT, min_version=None)))
        for source in ('ghsa', 'project', 'osv', 'nvd', 'cve'):
            self.assertEqual(identity(source, PRODUCT), identity(source, self.product))

    def test_negated_nvd_and_incomplete_osv_remain_visible(self):
        node = {'vulnerable': True, 'criteria': 'cpe:2.3:a:vendor:one:*:*:*:*:*:*:*:*',
                'versionEndExcluding': '2'}
        self.assertFalse(excluded(row([{'negate': True, 'cpeMatch': [node]}]), self.product))
        node = {'package': {'name': 'one_pkg', 'ecosystem': 'PyPI'}, 'ranges': [
            {'type': 'SEMVER', 'events': [{'fixed': '2'}]}]}
        self.assertFalse(excluded(row([node]), self.product))
        node['ranges'][0]['events'] = [{'introduced': '0'}, {'last_affected': '2'}]
        self.assertFalse(excluded(row([node]), self.product))
        node['ranges'][0]['events'] = [{'introduced': '0'}, {'limit': '2'}]
        self.assertTrue(excluded(row([node]), self.product))
