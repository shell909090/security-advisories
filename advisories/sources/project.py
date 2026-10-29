from advisories.source_common import *
import datetime as dt
import re
from advisories.project_sync import older_than, collect_project
NAME='project'
GLOBAL=False
SECURITY = re.compile(r'\b(?:CVE-\d{4}-\d+|GHSA-[\w-]+|vulnerabilit\w*|remote code execution|arbitrary code execution|sandbox (?:escape|bypass)|security (?:fix|patch|advisory)|authentication bypass|credential (?:theft|leak))\b', re.I)

def github_project(client, product, since=None, until=None):
    for repo in product['repositories']:
        root='https://api.github.com/repos/'+repo
        for a in client.paginate_github(root+'/security-advisories',{'per_page':100, 'sort':'updated', 'direction':'desc'}):
            if older_than(a, since):
                break
            yield gh_record(a,product)
        if not getattr(client,'include_releases',False):
            continue
        yield from security_releases(client, product, repo, root, until)


def collect(client, product, since, until, context):
    return collect_project(github_project, client, product, since, until, context)

MATCH_BASIS = 'exact-repository'


def security_releases(client, product, repo, root, until):
    for a in client.paginate_github(root+'/releases',{'per_page':100}):
        if a.get('draft'):continue
        date=a.get('published_at') or a.get('created_at')
        # Release list ordering is not guaranteed by publication date.
        # Re-read releases: their published_at does not reveal edits to old notes.
        if date and until and timestamp(date)>timestamp(until):continue
        body=a.get('body') or '';title=a.get('name') or a.get('tag_name') or ''
        if not SECURITY.search(title+'\n'+body):continue
        if a.get('prerelease'):title='[prerelease] '+title
        r=base(product,'release:'+repo+':'+str(a['id']),title,body,date,a.get('updated_at') or date,a.get('html_url'))
        # A release mentioning multiple CVEs is NOT an alias for any one CVE.
        r.update(kind='security-release',references=re.findall(r'https?://[^\s<>]+',body))
        yield r
