import unittest
from advisories.impact import sentence_tags
from advisories.versions import evidence_versions, node_versions


class FactsTests(unittest.TestCase):
    def test_effects_and_negation(self):
        self.assertEqual(sentence_tags('This does not allow remote code execution.'), set())
        self.assertEqual(sentence_tags('Arbitrary code execution.'), {'Code Execution'})
        self.assertEqual(sentence_tags('A remote attacker can execute arbitrary code outside the sandbox.'),
                         {'RCE', 'Sandbox Escape'})
        self.assertEqual(sentence_tags('Use-after-free causes a crash.'), {'UAF', 'Crash'})

    def test_ghsa_and_osv_versions(self):
        self.assertEqual(node_versions({'vulnerable_version_range': '< 2', 'first_patched_version': '2'}),
                         [('< 2', '2', '')])
        self.assertEqual(node_versions({'events': [{'introduced': '1'}, {'fixed': '2'},
                                                 {'introduced': '3'}, {'fixed': '4'}]}),
                         [('>= 1, < 2', '2', ''), ('>= 3, < 4', '4', '')])

    def test_project_patched_versions(self):
        self.assertEqual(node_versions({'vulnerable_version_range': '< 2', 'patched_versions': '2'}),
                         [('< 2', '2', '')])

    def test_cpe_exclusive_bound_is_not_assumed_fix(self):
        facts = node_versions({'vulnerable': True, 'versionEndExcluding': '2'})
        self.assertEqual(facts[0][:2], ('< 2', '未知'))

    def test_chrome_explicit_boundary(self):
        facts = evidence_versions({'description': 'Google Chrome prior to 156.0.8078.73 allowed a remote attacker...'})
        self.assertEqual(facts[0][:2], ('< 156.0.8078.73', '156.0.8078.73'))
