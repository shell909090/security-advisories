"""Product isolation must preserve legitimate components and raw detail evidence."""
import copy
import unittest
from advisories.version_summary import summarize
from advisories.versions import version_facts

PRODUCT = {'id': 'one', 'keywords': ['One'], 'vendors': ['vendor'],
           'packages': [{'ecosystem': 'PyPI', 'name': 'one_pkg'}]}


def row(affected, description=''):
    return {'evidence': [{'source': 'example', 'affected': affected, 'description': description}]}


def gh(name, ecosystem, fix):
    return {'package': {'name': name, 'ecosystem': ecosystem},
            'vulnerable_version_range': '< ' + fix, 'first_patched_version': fix}


class VersionScopeTests(unittest.TestCase):
    def test_package_and_ecosystem_isolation_without_mutating_evidence(self):
        item = row([gh('One.Pkg', 'pip', '2.0'), gh('other', 'pip', '99.0'),
                    gh('one_pkg', 'npm', '88.0')])
        before = copy.deepcopy(item)
        affected, fixed = summarize([item], PRODUCT)
        self.assertIn('2.0', fixed)
        self.assertNotIn('99.0', fixed)
        self.assertNotIn('88.0', affected)
        self.assertEqual(item, before)
        self.assertEqual(len(version_facts(item)), 3)

    def test_osv_nested_ranges_and_multiple_configured_packages(self):
        product = dict(PRODUCT, packages=PRODUCT['packages'] + [{'ecosystem': 'npm', 'name': '@org/cli'}])
        nodes = [{'package': {'ecosystem': eco, 'name': name}, 'ranges': [
            {'type': 'SEMVER', 'events': [{'introduced': '1'}, {'fixed': fix}]}]}
            for eco, name, fix in [('PyPI', 'one-pkg', '2'), ('npm', '@org/cli', '3'),
                                   ('npm', 'other', '99')]]
        affected, fixed = summarize([row(nodes)], product)
        self.assertIn('one-pkg: 2', fixed)
        self.assertIn('@org/cli: 3', fixed)
        self.assertNotIn('99', affected + fixed)

    def test_cve_components_platforms_and_vendor(self):
        nodes = [{'product': name, 'vendor': vendor, 'platforms': [platform],
                  'components': [{'name': 'engine', 'versions': [
                      {'version': '0', 'lessThan': bound, 'status': 'affected'}]}]}
                 for name, vendor, platform, bound in [('One', 'vendor', 'linux', '2'),
                     ('One', 'vendor', 'windows', '3'), ('Other', 'vendor', 'linux', '99'),
                     ('One', 'unrelated', 'linux', '88')]]
        affected, _ = summarize([row(nodes)], PRODUCT)
        self.assertIn('one / linux / engine: *, < 2', affected)
        self.assertIn('one / windows / engine: *, < 3', affected)
        self.assertNotIn('99', affected)
        self.assertNotIn('88', affected)

    def test_unknown_scope_cannot_supply_fix_and_chrome_prose_is_scoped(self):
        item = row([gh('other', 'pip', '99')], 'Google Chrome prior to 156.0.8078.73 has a bug.')
        affected, fixed = summarize([item], PRODUCT)
        self.assertEqual(affected, '未知/待核实')
        self.assertIn('1 条未提供明确修复版本', fixed)
        self.assertNotIn('156.', fixed)
        self.assertIn('156.0.8078.73', summarize([item], {'id': 'chrome'})[1])

    def test_cpe_product_and_vendor_filtering(self):
        nodes = [{'vulnerable': True, 'criteria': f'cpe:2.3:a:{vendor}:{name}:*:*:*:*:*:*:*:*',
                  'versionEndExcluding': bound} for vendor, name, bound in
                 [('vendor', 'one', '2'), ('vendor', 'other', '99'), ('other', 'one', '88')]]
        affected, _ = summarize([row([{'nodes': [{'cpeMatch': nodes}]}])], PRODUCT)
        self.assertEqual(affected, 'one: < 2')
