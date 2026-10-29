"""Offline display orchestration with post-output history persistence."""
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
    selected = [(p, row) for p, row in catalog_rows(args) if row['severity'] == args.severity]
    rows = [row for _, row in selected]
    label = selected[0][0].get('label', args.product) if selected else args.product
    emit(detail_format.render(label, args.severity, rows), args.output)
    return 0
