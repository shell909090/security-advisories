"""Batched lightweight indexes; fetch only new or modified OSV details."""
from urllib.parse import quote
from advisories.batch_sources import package_targets
from advisories.metrics import cache_hit
from advisories.osv_records import osv_record
from advisories.source_common import parse_time

NAME = 'osv'
GLOBAL = False
BATCH = True
MATCH_BASIS = 'exact-package'


def batch_index(client, targets):
    pending = [(key, {'package': target['package']}) for key, target in targets.items()]
    result = {key: {} for key in targets}
    seen_tokens = set()
    while pending:
        group, pending = pending[:100], pending[100:]
        response = client.json('https://api.osv.dev/v1/querybatch', data={'queries': [q for _, q in group]})
        rows = response.get('results', [])
        if len(rows) != len(group):
            raise ValueError('OSV batch response length mismatch')
        for (key, query), row in zip(group, rows):
            merge_index_page(result[key], row)
            extend_page(pending, seen_tokens, key, query, row)
    return result


def merge_index_page(index, page):
    if 'error' in page:
        raise ValueError('OSV index error: ' + str(page['error']))
    for item in page.get('vulns', []):
        if not item.get('id') or not item.get('modified'):
            raise ValueError('OSV index requires id and modified')
        index[item['id']] = item['modified']


def extend_page(pending, seen_tokens, key, query, row):
    token = row.get('next_page_token')
    if not token:
        return
    if (key, token) in seen_tokens:
        raise RuntimeError('OSV pagination loop')
    seen_tokens.add((key, token))
    pending.append((key, {**query, 'page_token': token}))


def detail_for(client, ident, modified, details):
    cached = details.get(ident)
    if cached and same_modified(cached['modified'], modified):
        cache_hit(client)
        return cached['record']
    record = client.json('https://api.osv.dev/v1/vulns/' + quote(ident, safe=''))
    if record.get('id') != ident or not record.get('modified'):
        raise ValueError('OSV detail identity/modified missing')
    # Detail can be newer than the index; cache actual version, never lie about its identity.
    details[ident] = {'modified': record['modified'], 'record': record}
    return record


def required_details(indexes):
    versions = {}
    for index in indexes.values():
        for ident, modified in index.items():
            versions[ident] = max(versions.get(ident, ''), modified)
    return versions


def collect_many(client, contexts, until, cache):
    targets = package_targets(contexts)
    indexes = batch_index(client, targets)
    details = dict(cache.get('details', {}))
    wanted = required_details(indexes)
    current = {ident: detail_for(client, ident, modified, details) for ident, modified in wanted.items()}
    results = assign_records(contexts, targets, indexes, current)
    return results, {'details': details, 'indexes': {**cache.get('indexes', {}), **indexes}}


def assign_records(contexts, targets, indexes, current):
    rows = {ident: {} for ident in contexts}
    for key, target in targets.items():
        for ident in indexes[key]:
            for product_id in target['products']:
                row = osv_record(current[ident], contexts[product_id]['product'])
                rows[product_id][ident] = row
    return {ident: {'records': list(items.values()), 'metadata': {}, 'replace_records': True}
            for ident, items in rows.items()}


def osv_product(client, product):
    results, _ = collect_many(client, {product['id']: {'product': product}}, None, {})
    yield from results[product['id']]['records']


def collect(client, product, since, until, context):
    return {'records': list(osv_product(client, product)), 'metadata': {}}


def same_modified(left, right):
    # querybatch timestamps are microseconds; details can preserve nanoseconds.
    try:
        return parse_time(left) == parse_time(right)
    except (ValueError, TypeError):
        return left == right
