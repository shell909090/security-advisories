"""Collect sources and maintain the product-scoped admission catalog."""
import datetime as dt
import sys
import time
from functools import partial
from .collector import collect_job, collection_jobs, execute_jobs, known_cves
from .http_client import Client
from .records import digest, merge_records
from .product_identity import product_confirmed
from .reporting import LEVEL
from .progress import clear_completed
from .sources import discover
from .storage import atomic_json, emit, load_products, load_state


def admitted(row, product, minimum):
    if row['withdrawn'] or LEVEL.get(row['severity'], -1) < LEVEL[minimum]:
        return False
    evidence = [e for e in row['evidence'] if e.get('kind') == 'vulnerability']
    scoped = dict(row, products=[product['id']], evidence=evidence)
    return product_confirmed(scoped, [product])


def refresh_catalog(state, products, minimum, errors, until):
    merged = merge_records(state['units'])
    catalog = state.setdefault('catalog', {})
    for product in products:
        rows = [dict(row, products=[product['id']]) for row in merged if admitted(row, product, minimum)]
        catalog[product['id']] = {'records': rows, 'min_severity': minimum,
                                  'updated_at': until.isoformat(), 'errors': errors}


def run(args):
    products = load_products(args)
    state = load_state(args.state)
    config_hash = digest({'products': products, 'min_severity': args.min_severity})
    until = dt.datetime.now(dt.timezone.utc)
    available = discover()
    jobs = collection_jobs(args, available, products, state)
    errors, completed = [], []
    started = time.monotonic()
    client = Client(args.timeout, args.proxy)
    collect = partial(collect_job, args=args, state=state, config_hash=config_hash,
                      until=until, available=available, client=client,
                      products=products, known=known_cves(state))
    try:
        execute_jobs(args, jobs, collect, state, completed, errors)
    finally:
        client.close()
    refresh_catalog(state, products, args.min_severity, errors, until)
    atomic_json(args.state, state)
    clear_completed(args.state, config_hash, completed)
    count = sum(len(state['catalog'][p['id']]['records']) for p in products)
    emit(f'Updated {len(products)} products; {count} admitted records; '
         f'{len(errors)} source failures; {time.monotonic() - started:.2f}s\n', args.output)
    for error in errors:
        print(f"WARNING {error['source']}: {error['error']}", file=sys.stderr)
    return int(bool(errors))
