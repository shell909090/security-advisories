"""Reject unsafe file collisions and invalid command ranges before running."""
import math
from .cache_storage import cache_path
from .locking import lock_path


def validate_update(parser, args):
    valid = (math.isfinite(args.overlap_days) and args.overlap_days >= 0
             and 1 <= args.workers <= 32 and 1 <= args.jobs <= 16
             and math.isfinite(args.timeout) and args.timeout > 0)
    if not valid:
        parser.error('Invalid overlap/workers/jobs/timeout')


def validate(parser, args):
    days = getattr(args, 'days', 3)
    if not math.isfinite(days) or days <= 0:
        parser.error('--days must be positive and finite')
    if args.command == 'update':
        validate_update(parser, args)
    if args.command == 'detail' and (not args.product or ',' in args.product):
        parser.error('detail requires exactly one --product')
    paths = [args.state, args.products, lock_path(args.state), cache_path(args.state),
             cache_path(args.state).with_name(cache_path(args.state).name + '.new'), args.state.with_name(args.state.name + '.cve-progress.json')]
    history = getattr(args, 'dedup_history', None)
    if history:
        paths.append(history)
    resolved = [p.resolve() for p in paths]
    if len(set(resolved)) != len(resolved):
        parser.error('State, configuration and history paths must be distinct')
    if args.output and args.output.resolve() in resolved:
        parser.error('Output must not overwrite state, configuration or history')
