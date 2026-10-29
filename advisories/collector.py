"""Concurrent source scheduling with independent product and batch checkpoints."""
import concurrent.futures
import datetime as dt
from pathlib import Path
import sys
import time
from .source_common import stamp
from .checkpoints import identity, window, cve_scope
from .cve_index import cve_window, updated_coverage
from .batch_sources import contexts
from .collection_results import normalize_result, record_changes
from .progress import CveProgress

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
        module = available[source]
        targets = [products] if getattr(module, 'BATCH', False) else [None] if module.GLOBAL else products
        for product in targets:
            key = source if product is None or isinstance(product, list) else source + ':' + product['id']
            jobs.append((source, product, key, state['units'].get(key, {})))
    jobs.sort(key=lambda j: not available[j[0]].GLOBAL)
    return jobs


def execute_jobs(args, jobs, collect, state, completed, errors):
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(collect, job): job[2] for job in jobs}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                updates, caches, stats = future.result()
                state['units'].update(updates)
                state.setdefault('source_caches', {}).update(caches)
                completed.append(stats)
                print(f'Done {key}: {stats["seconds"]}s', file=sys.stderr, flush=True)
            except Exception as exc:
                errors.append({'source': key, 'error': str(exc)})
                print(f'FAILED {key}: {exc}', file=sys.stderr, flush=True)


def finalized(key, result, old, module, fingerprint, until, client):
    rows, metadata, records = normalize_result(result, old, module)
    return {'checkpoint': stamp(until), 'collection_hash': fingerprint, 'records': records, **metadata}


def collect_batch(source, products, args, state, until, module, client):
    prepared = contexts(source, products, state, args, until)
    cache = state.get('source_caches', {}).get(source, {})
    results, cache = module.collect_many(client.for_source(source), prepared, until, cache)
    if set(results) != set(prepared):
        raise ValueError('Batch source returned incomplete product results')
    updates = {}
    for ident, context in prepared.items():
        key = source + ':' + ident
        updates[key] = finalized(key, results[ident], context['old'], module,
                                 context['collection_hash'], until, client)
    for ident, context in prepared.items():
        key = source + ':' + ident
        count_changes(client, source, results[ident], context['old'], updates[key])
    return updates, {source: cache}


def collect_single(job, args, state, until, module, client, products, known):
    source, product, key, old = job
    fingerprint = cve_scope(products) if product is None else identity(source, product)
    since, changed = window(args, old, fingerprint, until, getattr(module, 'SUPPORTS_FULL_HISTORY', True))
    if source == 'cve':
        since = cve_window(args, old, products, until)
    result = module.collect(client.for_source(source), product, since, until, {
        'products': products, 'old': old, 'known': known, 'workers': args.workers,
        'config_changed': changed, 'progress': CveProgress(args.state, fingerprint)})
    new = finalized(key, result, old, module, fingerprint, until, client)
    if source == 'cve':
        new['coverage'] = updated_coverage(old, products, until)
    count_changes(client, source, result, old, new)
    return {key: new}, {}


def collect_job(job, args, state, until, available, client, products, known):
    source, product, key, old = job
    began = time.monotonic()
    client.metrics.add(source)
    print(f'Fetching {key}', file=sys.stderr, flush=True)
    if isinstance(product, list):
        updates, caches = collect_batch(source, product, args, state, until, available[source], client)
    else:
        updates, caches = collect_single(job, args, state, until, available[source], client, products, known)
    return updates, caches, {'source': key, 'seconds': round(time.monotonic() - began, 2)}


def count_changes(client, source, result, old, new):
    removed = len(set(old.get('records', {})) - set(new['records']))
    client.metrics.add(source, removed=removed, **record_changes(result['records'], old))
