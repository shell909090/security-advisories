"""Independent severity, product identity, and output-history filters."""
import datetime as dt
from reporting import compact, LEVEL


from product_identity import product_confirmed


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
        if not eligible(row, args, products, stats, pending):
            continue
        item = filter_history(row, records, args, skip_dedup, cutoff, now, stats)
        if item is not None:
            changes.append(item)
    stats['reported']=len(changes)
    return changes,pending,stats


def is_recent(row, cutoff, now):
    recent = False
    for e in row.get('evidence', []):
        for key in ('published', 'modified'):
            try:
                date = dt.datetime.fromisoformat(e.get(key, '').replace('Z', '+00:00'))
                if date.tzinfo is None: date=date.replace(tzinfo=dt.timezone.utc)
                recent |= cutoff <= date <= now
            except (ValueError, TypeError): pass
    return recent


def eligible(row, args, products, stats, pending):
    skip_severity = getattr(args, "skip_severity_filter", False)
    skip_product = getattr(args, "skip_product_filter", False)
    if not skip_severity and LEVEL.get(row.get('severity', 'unknown'), -1) < LEVEL[getattr(args, 'min_severity', 'critical')]:
        stats['severity_filtered'] += 1
        if getattr(args, 'include_pending', False) and row.get('severity') == 'unknown':
            item=compact(row,'pending',getattr(args,'details',False));item['reason']='severity-unknown';pending.append(item)
        return False
    if not skip_product and not product_confirmed(row, products):
        stats['product_filtered'] += 1
        if getattr(args, 'include_pending', False):
            item=compact(row,'pending',getattr(args,'details',False));item['reason']='product-unconfirmed';pending.append(item)
        return False
    return True


def filter_history(row, records, args, skip_dedup, cutoff, now, stats):
    ident = row['id']
    previous = records.get(ident)
    fingerprint = row['fingerprint']
    changed = previous is not None and previous.get('fingerprint') != fingerprint
    recent = is_recent(row, cutoff, now)
    if not skip_dedup:
        records[ident] = {'fingerprint': fingerprint}
    if not getattr(args, 'history', False) and not recent and not changed:
        stats['history_filtered'] += 1
        return None
    if not skip_dedup and previous is not None and not changed:
        stats['duplicate_filtered'] += 1
        return None
    item=compact(row,'updated' if changed else 'new' if previous is None else 'unchanged',getattr(args,'details',False))
    kinds=sorted({e.get('kind','vulnerability') for e in row.get('evidence',[])})
    item['kind']=kinds[0] if len(kinds)==1 else 'mixed'
    return item
