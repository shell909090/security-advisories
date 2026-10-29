"""Recheck known NVD IDs periodically, independently of keyword discovery."""
import datetime as dt
import logging
from .source_common import parse_time, stamp

URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
INTERVAL = dt.timedelta(days=7)


def due(checked, until):
    if not checked:
        return True
    return until - parse_time(checked) >= INTERVAL


def batch_records(client, identifiers):
    wanted, found = set(identifiers), {}
    index = 0
    while True:
        params = {'cveIds': ','.join(identifiers), 'resultsPerPage': 100, 'startIndex': index}
        response = client.json(URL, params=params)
        total = response['totalResults']
        rows = response['vulnerabilities']
        if total != len(wanted) or not rows:
            raise ValueError('NVD known-ID review incomplete; cached records retained')
        for item in rows:
            raw = item['cve']
            ident = raw['id']
            if ident not in wanted or ident in found:
                raise ValueError('Unexpected or repeated NVD ID during review')
            found[ident] = raw
        index += len(rows)
        if index >= total:
            break
    return list(found.values())


def review(client, product, rows, old, until, normalize):
    current = {row['id']: row for row in rows}
    checked = dict(old.get('known_checked_at', {}))
    for ident in current:
        checked[ident] = stamp(until)
    pending = sorted(ident for ident in old.get('records', {})
                     if ident not in current and due(checked.get(ident), until))
    if pending:
        logging.getLogger(__name__).info('NVD %s: reviewing %s known IDs', product['id'], len(pending))
    for start in range(0, len(pending), 100):
        for raw in batch_records(client, pending[start:start + 100]):
            current[raw['id']] = normalize(raw, product)
            checked[raw['id']] = stamp(until)
    known = set(old.get('records', {})) | set(current)
    checked = {ident: date for ident, date in checked.items() if ident in known}
    return {'records': list(current.values()), 'metadata': {'known_checked_at': checked}}
