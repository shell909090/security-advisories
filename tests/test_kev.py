"""KEV window, identity, and conservative rating regressions."""
import datetime as dt
import unittest
from advisories.sources import kev


class KevTests(unittest.TestCase):
    def setUp(self):
        self.until = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)
        self.product = {'id': 'chrome', 'keywords': ['Chrome'], 'vendors': ['Google']}

    def item(self, date='2026-09-02', vendor='Google'):
        return dict(cveID='CVE-2026-12345', dateAdded=date, vendorProject=vendor,
                    product='Chrome', vulnerabilityName='Example', shortDescription='Evidence',
                    requiredAction='Apply updates', dueDate='2026-12-01')

    def test_boundaries(self):
        for date, count in [('2026-09-01', 0), ('2026-09-02', 1),
                            ('2026-11-02', 1), ('2026-11-03', 0)]:
            payload = {'count': 1, 'vulnerabilities': [self.item(date)]}
            self.assertEqual(len(kev.window_items(payload, self.until)), count)
        end = dt.datetime(2026, 4, 30, tzinfo=dt.timezone.utc)
        self.assertEqual(kev.cutoff(end), dt.date(2026, 2, 28))

    def test_products_and_unknown_rating(self):
        payload = {'count': 1, 'vulnerabilities': [self.item()]}
        class Client:
            def json(self, url):
                return payload
        contexts = {'chrome': {'product': self.product},
                    'other': {'product': {'id': 'other', 'keywords': ['Other']}}}
        results, _ = kev.collect_many(Client(), contexts, self.until, {})
        self.assertEqual(results['other']['records'], [])
        row = results['chrome']['records'][0]
        self.assertEqual(row['severity'], 'unknown')
        self.assertEqual(row['kev'], self.item())
        self.assertIn('Apply updates', row['description'])

    def test_incomplete_catalog_fails(self):
        with self.assertRaises(ValueError):
            kev.window_items({'count': 2, 'vulnerabilities': [self.item()]}, self.until)
        with self.assertRaises(ValueError):
            kev.window_items({'count': 2, 'vulnerabilities': [self.item()] * 2}, self.until)
