"""Normalize and compare committed source records."""
from .reporting import LEVEL
from .records import meaningful


def normalize_result(result, old, module):
    rows, metadata = result['records'], result.get('metadata', {})
    if not isinstance(rows, list) or not isinstance(metadata, dict):
        raise ValueError('Invalid source result: expected records list and metadata object')
    if set(metadata) & {'checkpoint', 'config_hash', 'collection_hash', 'records'}:
        raise ValueError('Source metadata contains reserved fields')
    records = {} if result.get('replace_records') else dict(old.get('records', {}))
    for row in rows:
        if not isinstance(row.get('id'), str) or not isinstance(row.get('products'), list):
            raise ValueError('Invalid normalized record identity/products')
        if row.get('severity') not in LEVEL or row.get('kind') not in ('vulnerability', 'security-release'):
            raise ValueError('Invalid normalized record severity/kind')
        row['match_basis'] = getattr(module, 'MATCH_BASIS', 'source-candidate')
        records[row['id']] = row
    return rows, metadata, records


def record_changes(rows, old):
    counts = dict(new=0, changed=0, unchanged=0)
    for row in {item['id']: item for item in rows}.values():
        previous = old.get('records', {}).get(row['id'])
        if previous is None:
            counts['new'] += 1
        elif meaningful(previous) != meaningful(row):
            counts['changed'] += 1
        else:
            counts['unchanged'] += 1
    return counts
