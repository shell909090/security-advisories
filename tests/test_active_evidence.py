"""Regression coverage for environment matches and withdrawn-source reporting."""
import datetime as dt
import unittest
from advisories.records import merge_records
from advisories.update import refresh_catalog
from advisories.summary import render
from advisories.detail import render_row
from advisories.filters import is_recent
from advisories.selection import display_fingerprint
from tests.command_support import record

PRODUCT = dict(id='one', label='ONE', keywords=['one'], packages=[], vendors=['vendor'])


def state_for(old, current):
    return {'units': {'ghsa:one': {'records': {old['id']: old}},
                      'nvd:one': {'records': {current['id']: current}}}}


def cpe(vulnerable):
    return {'vulnerable': vulnerable, 'criteria': 'cpe:2.3:a:vendor:one:*:*:*:*:*:*:*:*'}


class ActiveEvidenceTests(unittest.TestCase):
    def test_environment_not_admitted_but_vulnerable_sibling_is(self):
        item = record('CVE-2026-1234')
        item['affected'] = [{'nodes': [{'operator': 'AND', 'cpeMatch': [cpe(False)]}]}]
        state = {'units': {'nvd:one': {'records': {item['id']: item}}}}
        now = dt.datetime.now(dt.timezone.utc)
        refresh_catalog(state, [PRODUCT], 'high', [], now)
        self.assertEqual(state['catalog']['one']['records'], [])
        item['affected'][0]['nodes'][0]['cpeMatch'].append(cpe(True))
        refresh_catalog(state, [PRODUCT], 'high', [], now)
        self.assertEqual(len(state['catalog']['one']['records']), 1)

    def pair(self):
        old = record('GHSA-old')
        old.update(aliases=['CVE-2026-1234'], withdrawn=True)
        current = record('CVE-2026-1234', severity='high', date='2020-01-01T00:00:00Z')
        current.update(title='Crash', description='A crash.', affected=[
            {'package': {'name': 'one'}, 'vulnerable_version_range': '< 1.5',
             'first_patched_version': '1.5'}])
        return old, current

    def test_withdrawn_source_does_not_supply_rating_versions_or_tags(self):
        old, current = self.pair()
        row = merge_records(state_for(old, current)['units'])[0]
        self.assertEqual(row['severity'], 'high')
        self.assertFalse(row['withdrawn'])
        text = render([(PRODUCT, row)])
        self.assertIn('| ONE | 0 | 0 | 1 |', text)
        self.assertIn('1.5', text)
        self.assertNotIn('2.0', text)
        self.assertNotIn('RCE', text)
        detail = '\n'.join(render_row(1, row))
        self.assertNotIn('已撤回（不参与汇总）', detail)
        self.assertNotIn(old['description'], detail)

    def test_withdrawn_source_cannot_confirm_product_or_refresh_time(self):
        old, current = self.pair()
        current['affected'] = [dict(cpe(False))]
        state = state_for(old, current)
        now = dt.datetime.now(dt.timezone.utc)
        row = merge_records(state['units'])[0]
        self.assertFalse(is_recent(row, now - dt.timedelta(days=3), now))
        refresh_catalog(state, [PRODUCT], 'high', [], now)
        self.assertEqual(state['catalog']['one']['records'], [])
        fingerprint = display_fingerprint(row)
        old['description'] += ' More withdrawn content.'
        self.assertEqual(display_fingerprint(merge_records(state['units'])[0]), fingerprint)

    def test_official_rejection_and_all_withdrawn_still_remove_catalog(self):
        old, current = self.pair()
        old['withdrawn'] = False
        current['withdrawn'] = True
        self.assertTrue(merge_records(state_for(old, current)['units'])[0]['withdrawn'])
        old['withdrawn'] = True
        row = merge_records(state_for(old, current)['units'])[0]
        self.assertTrue(row['withdrawn'])
        self.assertEqual(row['severity'], 'unknown')
