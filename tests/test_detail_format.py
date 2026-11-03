"""Readable boundaries preserve branches and flag opaque source text."""
import unittest
from advisories.detail import readable_span, render_row, render


class DetailFormatTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(readable_span('>= 3.12.0, < 3.12.16'), '3.12.0 ≤ 版本 < 3.12.16')
        self.assertEqual(readable_span('>= 0, < 1.25.13'), '< 1.25.13')
        self.assertEqual(readable_span('cpe:2.3:a:postgresql:postgresql:15:beta1:*:*:*:*:*:*'),
                         '15 beta1')
        self.assertIn('待核实', readable_span('postgresql 14.5, postgresql 13.8'))

    def test_defect_is_not_consequence(self):
        row = {'id': 'CVE-test', 'evidence': [{'description': 'Use-after-free.',
               'url': 'https://example.org/advisory'}]}
        text = '\n'.join(render_row(1, row))
        self.assertIn('| 未知 | 未知 | https://example.org/advisory |', text)
        self.assertNotIn('UAF', text)

    def test_descriptions_precede_table_without_source_dump(self):
        row = {'id': 'CVE-test', 'evidence': [
            {'description': 'Withdrawn text', 'withdrawn': True},
            {'description': 'Original paragraph.\n\nSecond paragraph.',
             'scores': [{'secret-score': 9}], 'affected': []},
            {'description': 'Alternative description'}]}
        text = render('Product', 'high', [row])
        self.assertIn('> Original paragraph.\n> \n> Second paragraph.', text)
        self.assertLess(text.index('Original paragraph.'), text.index('| 漏洞 ID'))
        self.assertNotIn('Withdrawn text', text)
        self.assertNotIn('Alternative description', text)
        self.assertNotIn('secret-score', text)

    def test_missing_description(self):
        text = render('Product', 'high', [{'id': 'CVE-test', 'evidence': []}])
        self.assertIn('暂无原始描述', text)
