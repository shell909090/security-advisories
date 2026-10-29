NAME="osv"
GLOBAL=False

def osv_product(client, product):
    for package in product['packages']:
        payload = {'package': package}
        tokens = set()
        while True:
            response = client.json('https://api.osv.dev/v1/query', data=payload)
            if not isinstance(response, dict):
                raise ValueError('Unexpected OSV response')
            for record in response.get('vulns', []):
                yield {'id': record['id'], 'aliases': record.get('aliases', []),
                       'products': [product['id']], 'title': record.get('summary', record['id']),
                       'description': record.get('details', ''),
                       'severity': record.get('database_specific', {}).get('severity', 'unknown').lower(),
                       'scores': record.get('severity', []),
                       'published': record.get('published'), 'modified': record.get('modified'),
                       'url': 'https://osv.dev/vulnerability/' + record['id'],
                       'affected': record.get('affected', []), 'withdrawn': bool(record.get('withdrawn')),
                       'kind': 'vulnerability', 'references': [r['url'] for r in record.get('references', [])]}
            token = response.get('next_page_token')
            if not token:
                break
            if token in tokens:
                raise RuntimeError('OSV pagination loop')
            tokens.add(token)
            payload['page_token'] = token


def collect(client, product, since, until, context):
    return {"records": list(osv_product(client, product)), "metadata": {}}

MATCH_BASIS = 'exact-package'
