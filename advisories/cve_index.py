"""Retain inspections by local check time, not a CVE's historical modification time."""
from .source_common import parse_time, stamp
from .checkpoints import identity, window


def selected_hashes(products):
    return {p['id']: identity('cve', p) for p in products}


def retain_seen(previous, oldest, now):
    result = {}
    for ident, entry in previous.items():
        # Legacy timestamps have no inspection time or matching scope; refetch once.
        if not isinstance(entry, dict):
            continue
        if parse_time(entry['checked_at']) >= oldest:
            result[ident] = entry
    return result


def inspected(seen, entry, scopes):
    prior = seen.get(entry['cveId'], {})
    return (prior.get('modified') == entry['dateUpdated']
            and all(prior.get('products', {}).get(key) == value for key, value in scopes.items()))


def mark_seen(seen, entry, scopes, now):
    prior = seen.get(entry['cveId'], {})
    products = prior.get('products', {}) if prior.get('modified') == entry['dateUpdated'] else {}
    seen[entry['cveId']] = {'modified': entry['dateUpdated'], 'checked_at': stamp(now),
                           'products': {**products, **scopes}}


def cve_window(args, old, products, until):
    coverage = old.get('coverage', {})
    starts = [window(args, coverage.get(p['id'], {}), identity('cve', p), until, False)[0]
              for p in products]
    return min(starts)


def updated_coverage(old, products, until):
    coverage = dict(old.get('coverage', {}))
    for product in products:
        coverage[product['id']] = {'checkpoint': stamp(until), 'collection_hash': identity('cve', product)}
    return coverage
