"""Offline catalog selection and alias-aware, product-scoped display history."""
import datetime as dt
import sys
from .filters import is_recent
from .reporting import LEVEL
from .records import digest, meaningful
from .storage import load_products, load_state, read_json


def catalog_rows(args):
    products = load_products(args)
    state = load_state(args.state)
    if 'catalog' not in state:
        raise ValueError('No admission catalog; run update first')
    result = []
    for product in products:
        entry = state['catalog'].get(product['id'])
        if entry is None:
            print(f"WARNING {product['id']}: not collected; run update", file=sys.stderr)
            continue
        warn_coverage(args, product, entry)
        result.extend((product, row) for row in entry['records'] if not row.get('withdrawn'))
    return result


def warn_coverage(args, product, entry):
    minimum = getattr(args, 'min_severity', getattr(args, 'severity', 'critical'))
    if LEVEL[minimum] < LEVEL[entry['min_severity']]:
        print(f"WARNING {product['id']}: cache collected at {entry['min_severity']}; "
              f"run update --min-severity {minimum} for wider coverage", file=sys.stderr)
    if entry.get('errors'):
        print(f"WARNING {product['id']}: cached update had source failures; coverage may be stale", file=sys.stderr)


def read_history(args):
    if args.all:
        return {'version': 2, 'records': {}}
    history = read_json(args.dedup_history, {'version': 2, 'records': {}})
    # Old output-history entries have no product dimension; cannot prove summary delivery.
    if history.get('version') == 1:
        return {'version': 2, 'records': {}}
    if history.get('version') != 2:
        raise ValueError('Unsupported summary history version')
    return history


def history_keys(product, row):
    return [product['id'] + ':' + ident for ident in sorted(set([row['id']] + row['aliases']))]


def select_summary(args, candidates, history):
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=args.days)
    return [(product, row) for product, row in candidates
            if visible(args, product, row, history['records'], cutoff, now)]


def visible(args, product, row, records, cutoff, now):
    if LEVEL.get(row['severity'], -1) < LEVEL[args.min_severity]:
        return False
    previous = [records[key] for key in history_keys(product, row) if key in records]
    unchanged = any(item['fingerprint'] == display_fingerprint(row) for item in previous)
    changed = bool(previous) and not unchanged
    if not args.history and not is_recent(row, cutoff, now) and not changed:
        return False
    if args.all:
        return True
    if args.shown:
        return bool(previous)
    return not unchanged


def remember(history, selected):
    for product, row in selected:
        for key in history_keys(product, row):
            history['records'][key] = {'fingerprint': display_fingerprint(row)}


def display_fingerprint(row):
    evidence = []
    for item in row['evidence']:
        content = meaningful(item)
        content.pop('id', None)
        content.pop('aliases', None)
        if content['title'].startswith(('CVE-', 'GHSA-', 'GO-')):
            content['title'] = ''
        evidence.append({'source': item.get('source'), **content})
    return digest({'severity': row['severity'], 'withdrawn': row.get('withdrawn'),
                   'evidence': sorted(evidence, key=lambda item: digest(item))})
