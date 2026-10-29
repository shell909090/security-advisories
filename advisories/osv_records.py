"""Normalize OSV detail documents."""


def osv_record(record, product):
    return {'id': record['id'], 'aliases': record.get('aliases', []),
           'products': [product['id']], 'title': record.get('summary', record['id']),
           'description': record.get('details', ''),
           'severity': record.get('database_specific', {}).get('severity', 'unknown').lower(),
           'scores': record.get('severity', []),
           'published': record.get('published'), 'modified': record.get('modified'),
           'url': 'https://osv.dev/vulnerability/' + record['id'],
           'affected': record.get('affected', []), 'withdrawn': bool(record.get('withdrawn')),
           'kind': 'vulnerability', 'references': [r['url'] for r in record.get('references', [])]}
