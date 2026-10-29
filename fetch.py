#!/usr/bin/env python3
"""Collect product security intelligence, not installed-version vulnerability verdicts."""
import argparse
import concurrent.futures
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
UTC = dt.timezone.utc
LEVEL = {'unknown': -1, 'none': 0, 'low': 1, 'moderate': 2, 'medium': 2,
         'high': 3, 'critical': 4}
CVE_LOG = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json'


def stamp(value):
    return value.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def parse_time(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.new')
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    temporary.replace(path)


from http_client import Client


# Compatibility exports for library callers; implementations live with their source.
from source_common import product_matches, numeric_severity, metrics_scores
from sources.osv import osv_product
from sources.cve import cve_record, cve_delta


from records import merge_records, meaningful


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
    sources = [] if getattr(args, 'offline', False) else list(dict.fromkeys(args.sources.split(','))) if args.sources else list(available)
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
    result = available[source].collect(client, product, since, until, {
        'products': products, 'old': old, 'known': known, 'workers': args.workers,
        'config_changed': config_changed})
    rows, metadata, records = normalize_result(result, old, available[source])
    new = {'checkpoint': stamp(until), 'config_hash': config_hash, 'records': records, **metadata}
    return key, new, {'source': key, 'fetched_relevant': len(rows), 'stored': len(records),
                      'seconds': round(time.monotonic() - began, 2)}


def run(args):
    from sources import discover
    available = discover()
    products = json.loads(args.products.read_text())
    if not products or any(not p.get('id') or not p.get('packages') for p in products):
        raise ValueError('Invalid products configuration')
    state = json.loads(args.state.read_text()) if args.state.exists() else {'version': 1, 'units': {}, 'seen_output': {}}
    if state.get('version') != 1:
        raise ValueError('Unsupported state version')
    config_hash = digest(products)
    until = dt.datetime.now(UTC)
    client = Client(args.timeout, args.proxy)
    from filters import apply_filters
    dedup_enabled = not (getattr(args, "skip_dedup_filter", False) or args.all)
    dedup_path = getattr(args, "dedup_history", args.state.with_name("dedup-history.json"))
    history = json.loads(dedup_path.read_text()) if dedup_enabled and dedup_path.exists() else {"version": 1, "records": {}}
    if history.get("version") != 1:
        raise ValueError("Unsupported dedup history version")
    client.include_releases = getattr(args, 'include_releases', False)
    errors, completed = [], []
    started = time.monotonic()
    known = known_cves(state)
    jobs = collection_jobs(args, available, products, state)

    from functools import partial
    collect = partial(collect_job, args=args, state=state, config_hash=config_hash,
                      until=until, available=available, client=client, products=products, known=known)
    execute_jobs(args, jobs, collect, state, completed, errors)
    merged = merge_records(state['units'])
    changes, pending_review, filter_stats = apply_filters(merged, history, args, products)
    if not errors:
        state['config_hash'] = config_hash
    report = {'generated_at': stamp(until), 'available_sources': list(available), 'filters': filter_stats, 'scope': 'Product intelligence only; installed versions and exploitability not checked.',
              'coverage': {'cve_initial_days': args.days, 'other_sources': 'Recent updates by default; --history explicitly requests historical review.',
                           'unreviewed_ghsa': 'CVE/NVD discovery complements reviewed package feeds; not a global unreviewed GHSA crawl.'},
              'elapsed_seconds': round(time.monotonic() - started, 2),
              'completed': sorted(completed, key=lambda x: x['source']), 'errors': errors,
              'checkpoints': {key: unit.get('checkpoint') for key, unit in state['units'].items()},
              'changes': changes, 'pending_review': pending_review,
              'counts': {'known_merged': len(merged), 'reported': len(changes), 'pending_review': len(pending_review)}}
    # Persist output first. This is collection state, never a notification acknowledgement.
    if args.output:
        atomic_json(args.output, report)
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    if dedup_enabled:
        atomic_json(dedup_path, history)
    for obsolete in ('seen_output', 'reported_severe', 'reporting_baseline'):
        state.pop(obsolete, None)
    atomic_json(args.state, state)
    print(f"Finished: {len(merged)} known, {len(changes)} reported, {len(errors)} source failures", file=sys.stderr)
    return 1 if errors else 0


from cli import main


if __name__ == '__main__':
    sys.exit(main())
