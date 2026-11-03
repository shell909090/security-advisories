"""Offline display orchestration with post-output history persistence."""
import datetime as dt
from .filters import is_recent
from .evidence import priority
from . import detail as detail_format
from . import summary as summary_format
from .selection import catalog_rows, read_history, remember, select_summary
from .storage import atomic_json, emit


def summary(args):
    candidates = catalog_rows(args)
    history = read_history(args)
    selected = select_summary(args, candidates, history)
    emit(summary_format.render(selected), args.output)
    if selected and not args.all and not args.shown:
        remember(history, selected)
        atomic_json(args.dedup_history, history)
    return 0


def detail(args):
    selected = [(p, row) for p, row in catalog_rows(args) if priority(row) in ([args.severity] if args.severity else ['high', 'critical'])]
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = args.since or now - dt.timedelta(days=args.days)
    rows = [row for _, row in selected if args.history or is_recent(row, cutoff, now)]
    label = selected[0][0].get('label', args.product) if selected else args.product
    period = '全部历史' if args.history else f'{cutoff.isoformat()} 至 {now.isoformat()}'
    emit(detail_format.render(label, args.severity or 'High + Critical', rows, period,
                              selected[0][0] if selected else None), args.output)
    return 0
