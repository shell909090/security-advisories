"""Concurrent source scheduling and normalized incremental state."""
import concurrent.futures
import datetime as dt
from pathlib import Path
import sys
import time
from .reporting import LEVEL
from .source_common import stamp, parse_time

ROOT = Path(__file__).resolve().parents[1]
UTC = dt.timezone.utc


def known_cves(state):
    known = {}
    for unit in state['units'].values():
        for row in unit.get('records', {}).values():
            for ident in [row['id']] + row.get('aliases', []):
                if ident.startswith('CVE-'):
                    known.setdefault(ident, {'products': []})
                    known[ident]['products'] = sorted(set(known[ident]['products'] + row['products']))
    return known


def collection_jobs(args, available, products, state):
    jobs = []
    sources = list(dict.fromkeys(args.sources.split(','))) if args.sources else list(available)
    for source in sources:
        if source not in available:
            raise ValueError(f'Unknown source: {source}')
        for product in ([None] if available[source].GLOBAL else products):
            key = source if product is None else source + ':' + product['id']
            jobs.append((source, product, key, state['units'].get(key, {})))
    # Start the independent CVE stream early; never let slow NVD requests serialize other hosts.
    jobs.sort(key=lambda j: not available[j[0]].GLOBAL)

    return jobs


def normalize_result(result, old, module):
    rows, metadata = result['records'], result.get('metadata', {})
    if not isinstance(rows, list) or not isinstance(metadata, dict):
        raise ValueError('Invalid source result: expected records list and metadata object')
    if set(metadata) & {'checkpoint', 'config_hash', 'records'}:
        raise ValueError('Source metadata contains reserved fields')
    records = dict(old.get('records', {}))
    for row in rows:
        if not isinstance(row.get('id'), str) or not isinstance(row.get('products'), list):
            raise ValueError('Invalid normalized record identity/products')
        if row.get('severity') not in LEVEL or row.get('kind') not in ('vulnerability', 'security-release'):
            raise ValueError('Invalid normalized record severity/kind')
        row['match_basis'] = getattr(module, 'MATCH_BASIS', 'source-candidate')
        records[row['id']] = row
    return rows, metadata, records


def execute_jobs(args, jobs, collect, state, completed, errors):
    with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(args, 'jobs', 6)) as executor:
        futures = {executor.submit(collect, job): job[2] for job in jobs}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                key, new, stats = future.result()
                state['units'][key] = new
                completed.append(stats)
                print(f'Done {key}: {stats["seconds"]}s', file=sys.stderr, flush=True)
            except Exception as exc:
                errors.append({'source': key, 'error': str(exc)})
                print(f'FAILED {key}: {exc}', file=sys.stderr, flush=True)


def collect_job(job, args, state, config_hash, until, available, client, products, known):
    source, product, key, old = job
    began = time.monotonic()
    config_changed = bool(old) and old.get('config_hash', state.get('config_hash', config_hash)) != config_hash
    since = parse_time(args.since) if args.since else (
        parse_time(old['checkpoint']) - dt.timedelta(days=args.overlap_days)
        if old.get('checkpoint') and not config_changed else until - dt.timedelta(days=args.days))
    if getattr(args, 'history', False) and not args.since and getattr(available[source], 'SUPPORTS_FULL_HISTORY', True):
        since = None
    print(f'Fetching {key}', file=sys.stderr, flush=True)
    from advisories.progress import CveProgress
    progress = CveProgress(args.state, config_hash)
    result = available[source].collect(client, product, since, until, {
        'products': products, 'old': old, 'known': known, 'workers': args.workers,
        'config_changed': config_changed, 'progress': progress})
    rows, metadata, records = normalize_result(result, old, available[source])
    new = {'checkpoint': stamp(until), 'config_hash': config_hash, 'records': records, **metadata}
    return key, new, {'source': key, 'fetched_relevant': len(rows), 'stored': len(records),
                      'seconds': round(time.monotonic() - began, 2)}


