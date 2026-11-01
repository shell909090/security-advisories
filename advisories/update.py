"""Collect sources and maintain the product-scoped admission catalog."""
from .evidence import priority
import datetime as dt
import logging
import time
from functools import partial
from .collector import collect_job, collection_jobs, execute_jobs, known_cves
from .http_client import Client
from .http_cache import HttpCache
from .records import merge_records
from .checkpoints import cve_scope
from .product_identity import product_confirmed
from .reporting import LEVEL
from .progress import clear_completed
from .sources import discover
from .storage import save_state, emit, load_products, load_state


def admitted(row, product, minimum):
    if row['withdrawn'] or LEVEL.get(priority(row), -1) < LEVEL[minimum]:
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
    state = load_state(args.state, with_http=True)
    config_hash = cve_scope(products)
    until = dt.datetime.now(dt.timezone.utc)
    available = discover()
    jobs = collection_jobs(args, available, products, state)
    errors, completed = [], []
    started = time.monotonic()
    client = Client(args.timeout, args.proxy)
    previous_http = state.get('http_cache', {})
    client.cache = HttpCache(previous_http)
    collect = partial(collect_job, args=args, state=state,
                      until=until, available=available, client=client,
                      products=products, known=known_cves(state))
    interrupted = False
    try:
        execute_jobs(args, jobs, collect, state, completed, errors, client.cancel)
    except KeyboardInterrupt:
        interrupted = True
        client.cancel()
        finished = {item['source'] for item in completed}
        errors.extend({'source': job[2], 'error': 'interrupted'}
                      for job in jobs if job[2] not in finished)
        logging.getLogger(__name__).warning('Interrupted; saving completed sources')
    finally:
        client.close()
    refresh_catalog(state, products, args.min_severity, errors, until)
    state['last_update'] = {'generated_at': until.isoformat(), 'sources': client.metrics.snapshot(),
                            'errors': errors, 'elapsed_seconds': round(time.monotonic() - started, 2)}
    failed = {error['source'].split(':')[0] for error in errors}
    state['http_cache'] = client.cache.snapshot(previous_http, failed)
    save_state(args.state, state)
    clear_completed(args.state, config_hash, completed)
    count = sum(len(state['catalog'][p['id']]['records']) for p in products)
    emit(f'Updated {len(products)} products; {count} admitted records; '
         f'{len(errors)} source failures; {time.monotonic() - started:.2f}s\n', args.output)
    from .statistics import render_statistics
    logging.getLogger(__name__).info(render_statistics(state['last_update']['sources']))
    for error in errors:
        logging.getLogger(__name__).warning(f"{error['source']}: {error['error']}")
    return 130 if interrupted else int(bool(errors))
