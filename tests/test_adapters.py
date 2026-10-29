import unittest
from advisories.sources.project import github_project
from advisories.sources.ghsa import github_package
from advisories.sources.nvd import nvd_product,nvd_record
from advisories.sources.nvd import query_keywords
P={'id':'x','repositories':['o/r'],'packages':[],'keywords':['x']}
class Tests(unittest.TestCase):
 def test_nvd_alias_consolidation(self):
  self.assertEqual(query_keywords({'keywords':['OpenAI Codex','Codex CLI','openai/codex','@openai/codex']}),['codex'])
  self.assertEqual(query_keywords({'keywords':['Hermes Agent','hermes-agent']}),['hermes'])
  self.assertEqual(query_keywords({'keywords':['OpenCode','opencode-ai']}),['opencode'])
  self.assertEqual(query_keywords({'keywords':['Claude Code','claude-code']}),['claude'])
  self.assertEqual(query_keywords({'keywords':['foo','bar']}),['foo','bar'])
  self.assertEqual(query_keywords({'keywords':['Claude Code'],'nvd_keywords':['specific phrase']}),['specific phrase'])
 def test_release_order_and_no_alias_merge(self):
  class Client:
   include_releases=True
   def paginate_github(self,url,params):
    if url.endswith('security-advisories'):return []
    return [{'id':1,'published_at':'2020-01-01T00:00:00Z','body':'security fix'},{'id':2,'published_at':'2026-01-02T00:00:00Z','body':'CVE-2026-1234 and CVE-2026-2345'}]
  rows=list(github_project(Client(),P,'2026-01-01T00:00:00Z'))
  self.assertEqual(len(rows),2) # Old releases can gain security information later.
  self.assertTrue(all(r['aliases']==[] for r in rows))
 def test_release_history_is_opt_in(self):
  class Client:
   def paginate_github(self,url,params):
    if url.endswith('/releases'):raise AssertionError('release history should not be fetched')
    return []
  self.assertEqual(list(github_project(Client(),P)),[])
 def test_ghsa_modified_window(self):
  class Client:
   def paginate_github(self,url,params):
    self.params=params
    return []
  c=Client();p=dict(P,packages=[{'ecosystem':'PyPI','name':'x'}])
  list(github_package(c,p,'2026-10-27T00:00:00Z'))
  self.assertEqual(c.params['modified'],'>=2026-10-27')
  self.assertEqual(c.params['ecosystem'],'pip')
 def test_nvd_windows_and_pages(self):
  class Client:
   def __init__(self):self.calls=[]
   def json(self,url,params):
    self.calls.append(params)
    return {'totalResults':2,'vulnerabilities':[{'cve':{'id':'CVE-2026-'+str(params['startIndex'])}}]}
  c=Client();rows=list(nvd_product(c,P,'2026-01-01T00:00:00Z','2026-06-01T00:00:00Z'))
  self.assertEqual(len(rows),4);self.assertEqual([x['startIndex'] for x in c.calls],[0,1,0,1])
  self.assertEqual(c.calls[0]['lastModEndDate'],c.calls[2]['lastModStartDate'])
 def test_conflicting_scores_preserved(self):
  a={'id':'CVE-1','metrics':{'cvssMetricV31':[{'source':'a','cvssData':{'baseScore':5,'version':'3.1'}},{'source':'b','cvssData':{'baseScore':9.8,'version':'3.1'}}]}}
  r=nvd_record(a,P);self.assertEqual(r['severity'],'critical');self.assertEqual(len(r['scores']),2)
if __name__=='__main__':unittest.main()
