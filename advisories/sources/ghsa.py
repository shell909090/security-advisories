"""Batch global advisories by ecosystem and collection window."""
from advisories.source_common import gh_record, timestamp
from advisories.package_names import package_identity

NAME = 'ghsa'
GLOBAL = False
BATCH = True
MATCH_BASIS = 'exact-package'
ECOSYSTEMS = {'PyPI': 'pip', 'Go': 'go', 'crates.io': 'rust'}


def groups_for(contexts):
    groups = {}
    for ident, context in contexts.items():
        since = context['since']
        lower = timestamp(since).date().isoformat() if since else None
        for package in context['product']['packages']:
            ecosystem = ECOSYSTEMS.get(package['ecosystem'], package['ecosystem'])
            names = groups.setdefault((ecosystem, lower), {})
            names.setdefault(package['name'], set()).add(ident)
    return groups


def mapped_products(advisory, ecosystem, names):
    result = set()
    lookup = {package_identity(ecosystem, name): ids for name, ids in names.items()}
    for item in advisory.get('vulnerabilities', []):
        package = item.get('package') or {}
        if package.get('ecosystem') == ecosystem:
            result.update(lookup.get(package_identity(ecosystem, package.get('name', '')), set()))
    return result


def fetch_group(client, ecosystem, lower, names, until):
    params = {'ecosystem': ecosystem, 'affects': ','.join(names), 'type': 'reviewed', 'per_page': 100}
    if lower:
        upper = timestamp(until).date().isoformat() if until else None
        params['modified'] = lower + '..' + upper if upper else '>=' + lower
    yield from client.paginate_github('https://api.github.com/advisories', params)


def collect_many(client, contexts, until, cache):
    records = {ident: {} for ident in contexts}
    for (ecosystem, lower), names in groups_for(contexts).items():
        entries = list(names.items())
        # Bound query length; GitHub permits up to 1000 affects, URLs impose a tighter bound.
        for start in range(0, len(entries), 20):
            chunk = dict(entries[start:start + 20])
            for advisory in fetch_group(client, ecosystem, lower, chunk, until):
                for ident in mapped_products(advisory, ecosystem, chunk):
                    row = gh_record(advisory, contexts[ident]['product'])
                    records[ident][row['id']] = row
    return {ident: {'records': list(rows.values()), 'metadata': {}} for ident, rows in records.items()}, cache


def github_package(client, product, since=None, until=None):
    contexts = {product['id']: {'product': product, 'since': since}}
    results, _ = collect_many(client, contexts, until, {})
    yield from results[product['id']]['records']


def collect(client, product, since, until, context):
    return {'records': list(github_package(client, product, since, until)), 'metadata': {}}
