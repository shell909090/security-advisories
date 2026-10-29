"""Stable fingerprints and transitive advisory identity merging."""
import hashlib
import json
import re
from advisories.reporting import LEVEL

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def meaningful(record):
    """Ignore clocks/references/formatting, retain affected ranges, severity and withdrawal."""
    keys = ('id', 'aliases', 'products', 'title', 'description', 'severity', 'scores', 'affected', 'withdrawn', 'kind')
    result = {key: record.get(key) for key in keys}
    for key in ('title', 'description'):
        result[key] = re.sub(r'\s+', ' ', result.get(key) or '').strip()
    for key in ('aliases', 'products'):
        result[key] = sorted(result.get(key) or [])
    return result


def merge_records(units):
    parent = {}
    def find(x):
        parent.setdefault(x, x)
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]
    rows = []
    for unit, data in units.items():
        for record in data.get('records', {}).values():
            rows.append((unit, record))
            for alias in record.get('aliases', []):
                parent[find(alias)] = find(record['id'])
    groups = {}
    for unit, record in rows:
        groups.setdefault(find(record['id']), []).append((unit, record))
    result = []
    for rows in groups.values():
        ids = sorted({v for _, r in rows for v in [r['id']] + r.get('aliases', [])})
        identity = next((i for i in ids if i.startswith('CVE-')), ids[0])
        severity = max((r.get('severity', 'unknown') for _, r in rows), key=lambda s: LEVEL.get(s, -1))
        evidence = [{'source': u, **r} for u, r in sorted(rows, key=lambda x: (x[0], x[1]['id']))]
        statuses = {bool(r.get('withdrawn')) for _, r in rows}
        rejected = any(r.get('withdrawn') and r['id'].startswith('CVE-') and u.split(':')[0] in ('cve', 'nvd')
                       for u, r in rows)
        result.append({'id': identity, 'aliases': ids, 'products': sorted({p for _, r in rows for p in r['products']}),
                       'severity': severity, 'withdrawn': bool(rejected or statuses == {True}),
                       'withdrawal_conflict': len(statuses) > 1,
                       'needs_review': True, 'evidence': evidence,
                       'fingerprint': digest([{'source': u, **meaningful(r)} for u, r in sorted(rows, key=lambda x: (x[0], x[1]['id']))])})
    return sorted(result, key=lambda r: (-LEVEL.get(r['severity'], -1), r['id']))


