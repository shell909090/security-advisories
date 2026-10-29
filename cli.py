"""Command-line options, validation and process locking."""
import argparse
import contextlib
import fcntl
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def main():
    from fetch import run
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
    validate_args(parser, args)
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




def validate_args(parser, args):
    if args.days <= 0 or args.overlap_days < 0 or not 1 <= args.workers <= 32 or args.timeout <= 0 or not 1 <= args.jobs <= 16:
        parser.error('Invalid days/overlap/workers/timeout')
    if args.output and args.output.resolve() in (args.state.resolve(), args.products.resolve(), args.dedup_history.resolve()):
        parser.error('Output must not overwrite state, history or products')
    if args.dedup_history.resolve() in (args.state.resolve(), args.products.resolve()):
        parser.error('History must be separate from state and products')
