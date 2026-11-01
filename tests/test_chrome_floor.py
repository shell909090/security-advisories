"""Regression for Chrome CNA custom ranges seen in real cached advisories."""
import copy
import unittest
from advisories.version_floor import excluded


class ChromeFloorTests(unittest.TestCase):
    def setUp(self):
        self.product = {'id': 'chrome', 'keywords': ['Chrome'], 'vendors': ['google'],
                        'packages': [], 'min_version': '156.0.8078.80'}
        self.entry = {'version': '156.0.8078.79', 'lessThan': '156.0.8078.79',
                      'versionType': 'custom', 'status': 'affected'}
        self.evidence = {'source': 'cve', 'description':
                         'A bug in Google Chrome prior to 156.0.8078.79 allowed an attack.',
                         'affected': [{'vendor': 'Google', 'product': 'Chrome',
                                       'versions': [self.entry]}]}
        self.row = {'evidence': [self.evidence]}

    def test_corroborated_boundary_and_no_mutation(self):
        before = copy.deepcopy(self.row)
        self.assertTrue(excluded(self.row, self.product))
        self.assertEqual(self.row, before)
        self.product['min_version'] = '156.0.8078.79'
        self.assertTrue(excluded(self.row, self.product))
        self.product['min_version'] = '156.0.8078.78'
        self.assertFalse(excluded(self.row, self.product))

    def test_no_prose_or_different_boundary_stays_unknown(self):
        for text in ('', 'Google Chrome prior to 156.0.8078.73',
                     'Google Chrome prior to 156.0.8078.79rc1'):
            with self.subTest(text=text):
                self.evidence['description'] = text
                self.assertFalse(excluded(self.row, self.product))

    def test_changes_and_future_branch_are_not_hidden(self):
        self.entry['changes'] = [{'at': '156.0.8078.78', 'status': 'unaffected'}]
        self.assertFalse(excluded(self.row, self.product))
        self.entry.pop('changes')
        self.evidence['affected'][0]['versions'].append(
            {'version': '157.0', 'lessThan': '158.0', 'status': 'affected'})
        self.assertFalse(excluded(self.row, self.product))

    def test_other_products_and_conflicting_sources_remain_visible(self):
        self.product['id'] = 'other'
        self.assertFalse(excluded(self.row, self.product))
        self.product['id'] = 'chrome'
        self.row['evidence'].append({'affected': [{'vulnerable': True,
            'criteria': 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*',
            'versionEndExcluding': '157.0'}]})
        self.assertFalse(excluded(self.row, self.product))

    def test_empty_nvd_structure_uses_explicit_chrome_prose(self):
        nvd = {'source': 'nvd:chrome', 'affected': [{}],
               'description': 'A bug in Google Chrome on on Mac prior to 156.0.8078.79 allowed attacks.'}
        self.row['evidence'].append(nvd)
        self.assertTrue(excluded(self.row, self.product))
        nvd['affected'] = [{'unknown_range': 'unknown'}]
        self.assertFalse(excluded(self.row, self.product))
        nvd['affected'] = []
        nvd['description'] = ''
        self.assertFalse(excluded(self.row, self.product))
