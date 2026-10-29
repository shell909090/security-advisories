"""Per-source/product collection identity, independent of admission severity."""
import datetime as dt
from .records import digest
from .source_common import parse_time


def identity(source, product):
    fields = {'ghsa': ('packages',), 'osv': ('packages',),
              'project': ('repositories',), 'nvd': ('keywords', 'nvd_keywords')}
    names = fields.get(source, ('packages', 'repositories', 'keywords', 'vendors', 'vendor_aliases'))
    config = {name: product.get(name) for name in names}
    return digest({'source': source, 'product': product['id'], 'config': config})


def window(args, old, fingerprint, until, full_history=True):
    changed = old.get('collection_hash') != fingerprint
    if args.since:
        return parse_time(args.since), changed
    if args.history and full_history:
        return None, changed
    if old.get('checkpoint') and not changed:
        return parse_time(old['checkpoint']) - dt.timedelta(days=args.overlap_days), False
    return until - dt.timedelta(days=args.days), changed


def cve_scope(products):
    return digest(sorted((p['id'], identity('cve', p)) for p in products))
