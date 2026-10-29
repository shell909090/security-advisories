"""Independent severity, product identity, and output-history filters."""
import datetime as dt
import json
import re
from reporting import compact, LEVEL


def normalize(value):
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def product_confirmed(record, products):
    by_id = {p['id']: p for p in products}
    for e in record.get('evidence', []):
        source = e.get('source', '').split(':')[0]
        configured = set(by_id) & set(e.get('products', record.get('products', [])))
        exact = e.get('match_basis') in ('exact-package', 'exact-repository') or source in ('ghsa', 'osv', 'project')
        if configured and exact:
            return True
        for ident in record.get('products', []):
            p = by_id.get(ident)
            if not p:
                continue
            names = {normalize(v) for v in p.get('keywords', []) + [p.get('label', '')] + [q['name'] for q in p.get('packages', [])]}
            names.discard('')
            vendors = {normalize(v) for v in p.get('vendor_aliases', p.get('vendors', []))}
            def scan(value):
                if isinstance(value, list):
                    return any(scan(v) for v in value)
                if not isinstance(value, dict):
                    return False
                if vendors and value.get('vendor') and normalize(value['vendor']) not in vendors:
                    return False
                for key in ('product', 'packageName', 'name'):
                    if normalize(value.get(key, '')) in names:
                        return True
                vendor = value.get('vendor', '')
                if normalize(vendor+' '+value.get('product', '')) in names:
                    return True
                for key in ('criteria', 'cpe23Uri'):
                    cpe = value.get(key, '').split(':')
                    if len(cpe) > 4 and cpe[0] == 'cpe':
                        if vendors and normalize(cpe[3]) not in vendors:
                            continue
                        if normalize(cpe[4]) in names or normalize(cpe[3]+' '+cpe[4]) in names:
                            return True
                return any(scan(v) for v in value.values() if isinstance(v, (dict, list)))
            if scan(e.get('affected', [])):
                return True
    return False


def apply_filters(merged, history, args, products):
    now = getattr(args, 'now', None) or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=getattr(args, 'days', 3))
    skip_severity = getattr(args, 'skip_severity_filter', False)
    skip_product = getattr(args, 'skip_product_filter', False)
    skip_dedup = getattr(args, 'skip_dedup_filter', False) or getattr(args, 'all', False)
    records = {} if skip_dedup else history.setdefault('records', {})
    changes, pending = [], []
    stats = dict(input=len(merged), severity_filtered=0, product_filtered=0, history_filtered=0, duplicate_filtered=0, reported=0)
    for row in merged:
        ident = row['id']
        if not skip_severity and LEVEL.get(row.get('severity', 'unknown'), -1) < LEVEL[getattr(args, 'min_severity', 'critical')]:
            stats['severity_filtered'] += 1
            if getattr(args, 'include_pending', False) and row.get('severity') == 'unknown':
                item=compact(row,'pending',getattr(args,'details',False));item['reason']='severity-unknown';pending.append(item)
            continue
        if not skip_product and not product_confirmed(row, products):
            stats['product_filtered'] += 1
            if getattr(args, 'include_pending', False):
                item=compact(row,'pending',getattr(args,'details',False));item['reason']='product-unconfirmed';pending.append(item)
            continue
        previous = records.get(ident)
        fingerprint = row['fingerprint']
        changed = previous is not None and previous.get('fingerprint') != fingerprint
        recent = False
        for e in row.get('evidence', []):
            for key in ('published', 'modified'):
                try:
                    date = dt.datetime.fromisoformat(e.get(key, '').replace('Z', '+00:00'))
                    if date.tzinfo is None: date=date.replace(tzinfo=dt.timezone.utc)
                    recent |= cutoff <= date <= now
                except (ValueError, TypeError): pass
        if not skip_dedup:
            records[ident] = {'fingerprint': fingerprint}
        if not getattr(args, 'history', False) and not recent and not changed:
            stats['history_filtered'] += 1
            continue
        if not skip_dedup and previous is not None and not changed:
            stats['duplicate_filtered'] += 1
            continue
        item=compact(row,'updated' if changed else 'new' if previous is None else 'unchanged',getattr(args,'details',False))
        kinds=sorted({e.get('kind','vulnerability') for e in row.get('evidence',[])})
        item['kind']=kinds[0] if len(kinds)==1 else 'mixed'
        changes.append(item)
    stats['reported']=len(changes)
    return changes,pending,stats
