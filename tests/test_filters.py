import argparse
import copy
import datetime as dt
import unittest
from advisories.filters import apply_filters
P=[dict(id='claude',label='Claude Code',keywords=['claude-code'],packages=[],repositories=[])]
def args(**kw):return argparse.Namespace(**dict(dict(min_severity='critical',history=True,all=False,include_pending=False,days=3),**kw))
def row(source='ghsa:claude',severity='critical',affected=None):return dict(id='GHSA-x',aliases=[],products=['claude'],severity=severity,fingerprint='a',evidence=[dict(source=source,kind='vulnerability',affected=affected or [],title='Bug')])
class Tests(unittest.TestCase):
 def test_ghsa_without_cve(self):self.assertEqual(len(apply_filters([row()],{},args(),P)[0]),1)
 def test_keyword_not_identity(self):self.assertFalse(apply_filters([row('nvd:claude')],{},args(),P)[0])
 def test_cpe(self):self.assertTrue(apply_filters([row('nvd:claude',affected=[{'criteria':'cpe:2.3:a:anthropic:claude_code:*:*:*:*:*:*:*:*'}])],{},args(),P)[0])
 def test_independent_switches(self):
  self.assertFalse(apply_filters([row('nvd:claude','low')],{},args(skip_product_filter=True),P)[0])
  self.assertFalse(apply_filters([row('nvd:claude','low')],{},args(skip_severity_filter=True),P)[0])
  self.assertTrue(apply_filters([row('nvd:claude','low')],{},args(skip_product_filter=True,skip_severity_filter=True),P)[0])
 def test_dedup(self):
  h={};r=row();self.assertTrue(apply_filters([r],h,args(),P)[0]);r['evidence'][0]['modified']='2026-10-29'
  self.assertFalse(apply_filters([r],h,args(),P)[0]);r['fingerprint']='b';self.assertTrue(apply_filters([r],h,args(),P)[0])
 def test_skip_dedup_no_mutation(self):
  h={'records':{'GHSA-x':{'fingerprint':'a'}}};before=copy.deepcopy(h)
  self.assertTrue(apply_filters([row()],h,args(skip_dedup_filter=True),P)[0]);self.assertEqual(h,before)
if __name__=='__main__':unittest.main()
