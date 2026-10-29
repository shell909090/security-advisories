import unittest
from advisories.sources import discover


class SourceTests(unittest.TestCase):
    def test_discovery(self):
        modules = discover()
        self.assertEqual(set(modules), {'ghsa', 'project', 'nvd', 'osv', 'cve'})
        self.assertTrue(modules['cve'].GLOBAL)
        self.assertFalse(modules['osv'].GLOBAL)

    def test_unified_result(self):
        class Client:
            def json(self, *args, **kwargs):
                return {'vulns': [{'id': 'GHSA-test'}]}
        p = {'id': 'test', 'packages': [{'ecosystem': 'npm', 'name': 'test'}]}
        result = discover()['osv'].collect(Client(), p, None, None, {})
        self.assertEqual(set(result), {'records', 'metadata'})
        self.assertEqual(result['records'][0]['products'], ['test'])


if __name__ == '__main__':
    unittest.main()
