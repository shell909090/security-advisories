"""CISA KEV evidence from a fixed two-calendar-month admission window."""
import calendar
import datetime as dt
import re
from advisories.product_identity import affected_matches
from advisories.source_common import base

NAME = 'kev'
GLOBAL = False
BATCH = True
MATCH_BASIS = 'structured-product'
URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
PAGE = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'


def cutoff(until):
    current = until.astimezone(dt.timezone.utc).date()
    year, month = divmod(current.year * 12 + current.month - 3, 12)
    return current.replace(year=year, month=month + 1,
                           day=min(current.day, calendar.monthrange(year, month + 1)[1]))


def window_items(payload, until):
    items = payload['vulnerabilities']
    if not isinstance(items, list) or payload['count'] != len(items):
        raise ValueError('Incomplete KEV catalog')
    selected, seen = [], set()
    for item in items:
        ident = item['cveID']
        if not re.fullmatch(r'CVE-\d{4}-\d{4,19}', ident) or ident in seen:
            raise ValueError('Invalid or duplicate KEV identity')
        seen.add(ident)
        added = dt.date.fromisoformat(item['dateAdded'])
        if cutoff(until) <= added <= until.astimezone(dt.timezone.utc).date():
            selected.append(item)
    return selected


def record(item, product):
    description = '\n'.join(str(item.get(key, '')) for key in (
        'shortDescription', 'requiredAction', 'dueDate', 'knownRansomwareCampaignUse', 'notes'))
    row = base(product, item['cveID'], item['vulnerabilityName'], description,
               item['dateAdded'], item['dateAdded'], PAGE)
    row.update(affected=[{'vendor': item['vendorProject'], 'product': item['product']}],
               kev=dict(item))
    return row


def collect_many(client, contexts, until, cache):
    items = window_items(client.json(URL), until)
    results = {}
    for ident, context in contexts.items():
        product = context['product']
        rows = [record(item, product) for item in items]
        results[ident] = {'records': [row for row in rows if affected_matches(row, product)],
                          'metadata': {}}
    return results, {}


def collect(client, product, since, until, context):
    results, _ = collect_many(client, {product['id']: {'product': product}}, until, {})
    return results[product['id']]
