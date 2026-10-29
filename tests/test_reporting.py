import unittest
from reporting import compact

class Tests(unittest.TestCase):
    def test_explicit_identifiers_and_optional_evidence(self):
        r = {'id':'CVE-2026-1234', 'aliases':['GHSA-example'], 'products':['codex'],
             'severity':'critical', 'evidence':[{'source':'ghsa:codex','title':'Example',
             'url':'https://example.test','scores':[{'score':9.8}]}]}
        out = compact(r, 'new')
        self.assertEqual(out['cve_ids'], ['CVE-2026-1234'])
        self.assertEqual(out['ghsa_ids'], ['GHSA-example'])
        self.assertNotIn('evidence', out)
        self.assertIn('evidence', compact(r, 'new', True))

if __name__ == '__main__':
    unittest.main()
