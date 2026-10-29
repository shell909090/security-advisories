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


class Client:
    def __init__(self, timeout=30, proxy=None):
        self.timeout = timeout
        self.proxy = proxy
        self.nvd_lock = threading.Lock()
        self.nvd_last = 0.0

    def json(self, url, params=None, data=None, with_link=False):
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params, doseq=True)
        host = urllib.parse.urlparse(url).hostname
        headers = {'User-Agent': 'product-security-advisories/1.0', 'Accept': 'application/json'}
        if host == 'api.github.com':
            token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
            if token:
                headers['Authorization'] = 'Bearer ' + token
            headers['X-GitHub-Api-Version'] = '2022-11-28'
        if host == 'services.nvd.nist.gov' and os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        body = None if data is None else json.dumps(data).encode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
        for attempt in range(3):
            if host == 'services.nvd.nist.gov':
                with self.nvd_lock:
                    interval = 0.7 if os.environ.get('NVD_API_KEY') else 6.2
                    time.sleep(max(0, interval - (time.monotonic() - self.nvd_last)))
                    self.nvd_last = time.monotonic()
            request = urllib.request.Request(url, data=body, headers=headers)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy})
            ) if self.proxy else urllib.request.build_opener()
            try:
                with opener.open(request, timeout=self.timeout) as response:
                    result = json.load(response)
                    return (result, response.headers.get('Link', '')) if with_link else result
            except urllib.error.HTTPError as exc:
                if attempt < 2 and exc.code in (429, 500, 502, 503, 504):
                    time.sleep(min(30, 2 ** (attempt + 1)))
                    continue
                raise RuntimeError(f'HTTP {exc.code}: {host}{urllib.parse.urlparse(url).path}') from None
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f'Network failure: {host} ({type(exc).__name__})') from None

    def paginate_github(self, url, params=None):
        params = {**(params or {}), 'per_page': 100}
        visited = set()
        for _ in range(1000):
            batch, link = self.json(url, params, with_link=True)
            if not isinstance(batch, list):
                raise ValueError('Unexpected GitHub response')
            yield from batch
            next_link = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not next_link:
                return
            url = next_link.group(1)
            if urllib.parse.urlparse(url).hostname != 'api.github.com' or url in visited:
                raise RuntimeError('Invalid or repeated GitHub pagination URL')
            visited.add(url)
            params = None
        raise RuntimeError('GitHub pagination safety limit reached; checkpoint not advanced')


# Compatibility exports for library callers; implementations live with their source.
from source_common import product_matches, numeric_severity, metrics_scores
from sources.osv import osv_product
from sources.cve import cve_record, cve_delta


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
    known = {}
    for unit in state['units'].values():
        for row in unit.get('records', {}).values():
            for ident in [row['id']] + row.get('aliases', []):
                if ident.startswith('CVE-'):
                    known.setdefault(ident, {'products': []})
                    known[ident]['products'] = sorted(set(known[ident]['products'] + row['products']))
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

    def collect(job):
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
            row['match_basis'] = getattr(available[source], 'MATCH_BASIS', 'source-candidate')
            records[row['id']] = row
        new = {'checkpoint': stamp(until), 'config_hash': config_hash, 'records': records, **metadata}
        return key, new, {'source': key, 'fetched_relevant': len(rows), 'stored': len(records),
                          'seconds': round(time.monotonic() - began, 2)}

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--products', type=Path, default=ROOT / 'products.json')
    parser.add_argument('--state', type=Path, default=ROOT / 'state.json')
    parser.add_argument('--sources', help='Comma-separated discovered sources; default all')
    parser.add_argument('--list-sources', action='store_true')
    parser.add_argument('--days', type=float, default=3, help='Initial CVE delta lookback, at most available ~30 days')
    parser.add_argument('--overlap-days', type=float, default=2)
    parser.add_argument('--since', help='Explicit ISO date/time; override checkpoints for this run')
    parser.add_argument('--min-severity', choices=['low', 'medium', 'high', 'critical'], default='critical')
    parser.add_argument('--skip-severity-filter', action='store_true')
    parser.add_argument('--skip-product-filter', action='store_true')
    parser.add_argument('--skip-dedup-filter', action='store_true')
    parser.add_argument('--dedup-history', type=Path, default=ROOT / 'dedup-history.json')
    parser.add_argument('--all', action='store_true', help='Alias for --skip-dedup-filter')
    parser.add_argument('--history', action='store_true', help='Explicitly include historical advisories')
    parser.add_argument('--include-pending', action='store_true', help='Show unscored leads separately')
    parser.add_argument('--include-releases', action='store_true', help='Also crawl release notes (slow, not vulnerability records)')
    parser.add_argument('--details', action='store_true', help='Include full source evidence')
    parser.add_argument('--offline', action='store_true', help='Only render cached records')
    parser.add_argument('--jobs', type=int, default=6, help='Concurrent product/source collectors')
    parser.add_argument('--output', type=Path, help='Optional JSON output file; default stdout')
    parser.add_argument('--proxy', help='HTTP proxy URL; standard proxy environment variables also work')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--workers', type=int, default=8, help='CVE detail download concurrency')
    args = parser.parse_args()
    if args.list_sources:
        from sources import discover
        print('\n'.join(discover()))
        return 0
    if args.days <= 0 or args.overlap_days < 0 or not 1 <= args.workers <= 32 or args.timeout <= 0 or not 1 <= args.jobs <= 16:
        parser.error('Invalid days/overlap/workers/timeout')
    if args.output and args.output.resolve() in (args.state.resolve(), args.products.resolve(), args.dedup_history.resolve()):
        parser.error('Output must not overwrite state, history or products')
    if args.dedup_history.resolve() in (args.state.resolve(), args.products.resolve()):
        parser.error('History must be separate from state and products')
    args.state.parent.mkdir(parents=True, exist_ok=True)
    lock_paths = [args.state]
    if not args.skip_dedup_filter and not args.all:
        lock_paths.append(args.dedup_history)
    with contextlib.ExitStack() as stack:
        for path in sorted(lock_paths):
            path.parent.mkdir(parents=True, exist_ok=True)
            lock = stack.enter_context(path.with_suffix(path.suffix + '.lock').open('a'))
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                parser.exit(2, 'Another collector is using this state/history file\n')
        try:
            return run(args)
        except Exception as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 2


if __name__ == '__main__':
    sys.exit(main())
