from source_common import *
import datetime as dt
import re
import concurrent.futures
import sys
NAME="cve"
GLOBAL=True
CVE_LOG="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"

def cve_record(raw, products):
    meta = raw['cveMetadata']
    containers = raw.get('containers', {})
    blocks = [containers.get('cna', {})] + containers.get('adp', [])
    descriptions = [d['value'] for b in blocks for d in b.get('descriptions', []) if d.get('lang', '').startswith('en')]
    scores = [s for b in blocks for s in metrics_scores(b.get('metrics', []), b.get('providerMetadata', {}).get('shortName', 'CNA'))]
    return {'id': meta['cveId'], 'aliases': [], 'products': products,
            'title': containers.get('cna', {}).get('title', meta['cveId']),
            'description': '\n'.join(dict.fromkeys(descriptions)),
            'severity': numeric_severity(max(s['score'] for s in scores)) if scores else 'unknown',
            'scores': scores, 'published': meta.get('datePublished'), 'modified': meta.get('dateUpdated'),
            'url': 'https://www.cve.org/CVERecord?id=' + meta['cveId'],
            'affected': [a for b in blocks for a in b.get('affected', [])],
            'withdrawn': meta.get('state') == 'REJECTED', 'kind': 'vulnerability',
            'references': sorted({r['url'] for b in blocks for r in b.get('references', [])})}


def cve_delta(client, products, since, until, previous_seen, previous_records, workers):
    batches = client.json(CVE_LOG)
    if not isinstance(batches, list) or not batches:
        raise ValueError('Empty or invalid CVE delta log')
    oldest = min(parse_time(b['fetchTime']) for b in batches)
    if since < oldest:
        raise RuntimeError(f'CVE coverage gap: requested {stamp(since)}, delta log begins {stamp(oldest)}; use --since explicitly after backfill')
    entries = delta_entries(batches, since, until)
    seen = {k: v for k, v in previous_seen.items() if parse_time(v) >= oldest}
    pending = [entry for key, entry in entries.items() if seen.get(key) != entry['dateUpdated']]
    print(f'cve: {len(pending)} changed records to inspect', file=sys.stderr, flush=True)
    records = []
    def fetch(entry):
        # Construct trusted raw URL; do not fetch URLs supplied inside vulnerability prose.
        match = re.fullmatch(r'CVE-(\d{4})-(\d{4,})', entry['cveId'])
        if not match:
            raise ValueError('Invalid CVE ID')
        year, number = match.groups()
        url = f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{number[:-3]}xxx/{entry["cveId"]}.json'
        raw = client.json(url)
        hits = product_matches(raw, products)
        # Keep rejected records even if their description no longer names the product.
        if not hits:
            hits = previous_records.get(entry['cveId'], {}).get('products', [])
        return entry, cve_record(raw, hits) if hits else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for index, (entry, record) in enumerate(executor.map(fetch, pending), 1):
            seen[entry['cveId']] = entry['dateUpdated']
            if record:
                records.append(record)
            if index % 250 == 0:
                print(f'cve: {index}/{len(pending)} inspected', file=sys.stderr, flush=True)
    return records, seen


def collect(client, product, since, until, context):
    old=context.get('old', {})
    seen={} if context.get('config_changed') else old.get('cve_seen', {})
    records, seen=cve_delta(client, context['products'], since, until, seen,
                            context.get('known', {}), context.get('workers',8))
    return {'records':records, 'metadata':{'cve_seen':seen}}

MATCH_BASIS = 'product-description-or-reference'
SUPPORTS_FULL_HISTORY = False


def delta_entries(batches, since, until):
    entries = {}
    # Do not trust ordering; select by ingestion time, not the record publication date.
    for batch in batches:
        if since <= parse_time(batch['fetchTime']) <= until:
            for entry in batch.get('new', []) + batch.get('updated', []):
                key = entry['cveId']
                if key not in entries or entry['dateUpdated'] > entries[key]['dateUpdated']:
                    entries[key] = entry
    return entries
