from advisories.source_common import *
import datetime as dt
import re
import concurrent.futures
import sys
from advisories.cve_index import retain_seen, inspected, mark_seen, selected_hashes
from advisories.metrics import cache_hit
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


def cve_delta(client, products, since, until, previous_seen, previous_records, workers, progress=None):
    batches = client.json(CVE_LOG)
    if not isinstance(batches, list) or not batches:
        raise ValueError('Empty or invalid CVE delta log')
    oldest = min(parse_time(b['fetchTime']) for b in batches)
    if since < oldest:
        raise RuntimeError(f'CVE coverage gap: requested {stamp(since)}, delta log begins {stamp(oldest)}; use --since explicitly after backfill')
    cached = progress.load() if progress else {}
    previous_seen = {**previous_seen, **cached.get('seen', {})}
    entries = delta_entries(batches, since, until)
    scopes = selected_hashes(products)
    seen = retain_seen(previous_seen, oldest, until)
    pending = [entry for entry in entries.values() if not inspected(seen, entry, scopes)]
    cache_hit(client, len(entries) - len(pending))
    print(f'cve: {len(pending)} changed records to inspect', file=sys.stderr, flush=True)
    records = list(cached.get('records', []))
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
        selected = {p['id'] for p in products}
        previous = previous_records.get(entry['cveId'], {}).get('products', [])
        if not hits:
            hits = [ident for ident in previous if ident in selected]
        hits = sorted(set(hits) | (set(previous) - selected))
        return entry, cve_record(raw, hits) if hits else None
    download_batches(fetch, pending, workers, records, seen, progress, scopes)
    return records, seen


def collect(client, product, since, until, context):
    old=context.get('old', {})
    seen=old.get('cve_seen', {})
    records, seen=cve_delta(client, context['products'], since, until, seen,
                            context.get('known', {}), context.get('workers',8), context.get('progress'))
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


def download_batches(fetch, pending, workers, records, seen, progress, scopes=None, now=None):
    # Bound queued work and persist successful results even if a peer fails.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for start in range(0, len(pending), 100):
            batch = pending[start:start + 100]
            error = consume_batch(executor, fetch, batch, records, seen, scopes or {}, now or dt.datetime.now(dt.timezone.utc))
            if progress:
                progress.save(records, seen)
            print(f'cve: {start + len(batch)}/{len(pending)} inspected', file=sys.stderr, flush=True)
            if error:
                raise error


def consume_batch(executor, fetch, batch, records, seen, scopes, now):
    error = None
    futures = [executor.submit(fetch, entry) for entry in batch]
    for future in concurrent.futures.as_completed(futures):
        try:
            entry, record = future.result()
            mark_seen(seen, entry, scopes, now)
            if record:
                records.append(record)
        except Exception as exc:
            error = exc
    return error
