"""Range simplification must not lose affected versions or component boundaries."""
import unittest
from advisories.version_ranges import merge_spans
from advisories.version_summary import render_groups


class RangeTests(unittest.TestCase):
    def test_conjunction(self):
        self.assertEqual(merge_spans(['>=1, >=2, <5, <=4']), ['>= 2, <= 4'])

    def test_union_and_absorption(self):
        self.assertEqual(merge_spans(['>=1', '>=2']), ['>= 1'])
        self.assertEqual(merge_spans(['>=1, <3', '>=2, <4']), ['>= 1, < 4'])

    def test_open_boundary_and_gap(self):
        self.assertEqual(merge_spans(['<2', '>2']), ['< 2', '> 2'])
        self.assertEqual(merge_spans(['<2', '>=2']), ['*'])
        self.assertEqual(merge_spans(['<1', '>=2']), ['< 1', '>= 2'])

    def test_numeric_order_and_equivalence(self):
        self.assertEqual(merge_spans(['>=1.9, >=1.10', '>=1.10.0']), ['>= 1.10.0'])

    def test_opaque_and_contradictory_preserved(self):
        for span in ['>=2, <1', '^1.2', '>=1.0rc1', '>=1（未提供修复边界）']:
            self.assertEqual(merge_spans([span]), [span])

    def test_disjunction(self):
        self.assertEqual(merge_spans(['<2 || >=3', '<1']), ['< 2', '>= 3'])

    def test_component_and_platform_isolation(self):
        text = render_groups({'a/linux': ['>=1', '>=2'], 'a/windows': ['>=3'], 'b': ['<4']})
        self.assertEqual(text, 'a/linux: >= 1; a/windows: >= 3; b: < 4')

    def test_fixed_points_not_highest_only(self):
        self.assertEqual(merge_spans(['2.0', '3.0']), ['2.0', '3.0'])
        self.assertEqual(merge_spans(['>=2', '3.0']), ['>= 2'])

    def test_chrome_case_and_cumulative_fixes(self):
        from advisories.version_summary import summarize
        from unittest.mock import patch
        facts = [
            ('<156.0.8078.73', '156.0.8078.73', 'Chrome', 'ghsa'),
            ('<156.0.8078.47', '156.0.8078.47', 'chrome', 'cve'),
            ('<148.0.7778.96', '148.0.7778.96', 'Chrome', 'cve'),
        ]
        with patch('advisories.version_summary.version_facts', return_value=facts):
            affected, fixes = summarize([{}], {'id': 'chrome'})
        self.assertEqual(affected, 'chrome: < 156.0.8078.73')
        self.assertEqual(fixes, 'chrome: 156.0.8078.73')

    def test_cumulative_fixes_preserve_groups_and_opaque_versions(self):
        text = render_groups({'chrome/linux': ['9.0', '10.0'],
                              'chrome/windows': ['8.0'],
                              'chrome/lts': ['7.0', '7.1rc1']}, cumulative=True)
        self.assertEqual(text, 'chrome/linux: 10.0; chrome/lts: 7.0; chrome/lts: 7.1rc1; chrome/windows: 8.0')
