"""Confirm affected product identities from structured source evidence."""
import re
from .evidence import active_evidence


def normalize(value):
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def cpe_matches(text, names, vendors):
    cpe = text.split(':')
    if len(cpe) <= 4 or cpe[0] != 'cpe':
        return False
    if vendors and normalize(cpe[3]) not in vendors:
        return False
    return normalize(cpe[4]) in names or normalize(cpe[3] + ' ' + cpe[4]) in names


def identity_matches(value, names, vendors):
    if any(normalize(value.get(key, '')) in names for key in ('product', 'packageName', 'name')):
        return True
    if normalize(value.get('vendor', '') + ' ' + value.get('product', '')) in names:
        return True
    return any(cpe_matches(value.get(key, ''), names, vendors) for key in ('criteria', 'cpe23Uri'))


def scan(value, names, vendors):
    if isinstance(value, list):
        return any(scan(v, names, vendors) for v in value)
    if not isinstance(value, dict) or value.get('vulnerable') is False:
        return False
    if vendors and value.get('vendor') and normalize(value['vendor']) not in vendors:
        return False
    if identity_matches(value, names, vendors):
        return True
    return any(scan(v, names, vendors) for v in value.values() if isinstance(v, (dict, list)))


def affected_matches(evidence, product):
    p = product
    names = {normalize(v) for v in p.get('keywords', []) + [p.get('label', '')] + [q['name'] for q in p.get('packages', [])]}
    names.discard('')
    vendors = {normalize(v) for v in p.get('vendor_aliases', p.get('vendors', []))}
    return scan(evidence.get('affected', []), names, vendors)


def evidence_confirmed(evidence, record, by_id):
    e = evidence
    source = e.get('source', '').split(':')[0]
    configured = set(by_id) & set(e.get('products', record.get('products', [])))
    exact = e.get('match_basis') in ('exact-package', 'exact-repository') or source in ('ghsa', 'osv', 'project')
    if configured and exact:
        return True
    return any(affected_matches(e, by_id[ident])
               for ident in record.get('products', []) if ident in by_id)


def product_confirmed(record, products):
    by_id = {p['id']: p for p in products}
    return any(evidence_confirmed(e, record, by_id) for e in active_evidence(record))


