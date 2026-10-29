from advisories.source_common import *
import datetime as dt
import re
NAME='ghsa'
GLOBAL=False

def github_package(client, product, since=None, until=None):
    # First run may request history; subsequent windows include new and updated records.
    for package in product['packages']:
        eco={'PyPI':'pip','Go':'go','crates.io':'rust'}.get(package['ecosystem'],package['ecosystem'])
        params={'ecosystem':eco,'affects':package['name'],'type':'reviewed','per_page':100}
        if since:
            # GitHub rejects fractional-second timestamps here. A UTC day boundary
            # deliberately overlaps the checkpoint; content fingerprints dedupe it.
            params['modified']='>='+timestamp(since).astimezone(dt.timezone.utc).date().isoformat()
        for a in client.paginate_github('https://api.github.com/advisories',params):
            yield gh_record(a,product)


def collect(client, product, since, until, context):
    return {"records": list(github_package(client, product, since, until)), "metadata": {}}

MATCH_BASIS = 'exact-package'
