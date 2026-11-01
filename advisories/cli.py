"""Single entry point with independent collection and offline display commands."""
import argparse
import logging
from pathlib import Path
from . import update, views
from .locking import locked
from .validation import validate
from .source_common import parse_time
ROOT = Path(__file__).resolve().parents[1]
LEVELS = ['low', 'medium', 'high', 'critical']


def common(parser):
    parser.add_argument('--products', type=Path, default=ROOT / 'products.json', help='Product configuration file')
    parser.add_argument('--state', type=Path, default=ROOT / 'state.json')
    parser.add_argument('--product', help='Product ID; comma-separated for update/summary')
    parser.add_argument('--output', type=Path)


def update_options(parser):
    parser.add_argument('--sources', help='Comma-separated source names; default all')
    parser.add_argument('--min-severity', choices=LEVELS, default='high')
    parser.add_argument('--days', type=float, default=3)
    parser.add_argument('--since', help='Explicit ISO collection start')
    parser.add_argument('--overlap-days', type=float, default=2)
    parser.add_argument('--history', action='store_true', help='Backfill full history where supported')
    parser.add_argument('--jobs', type=int, default=6)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--cve-bundle', choices=['auto', 'off'], default='auto')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--proxy')


def summary_options(parser):
    parser.add_argument('--ignore-min-version', action='store_true',
                        help='Skip configured minimum-version filtering for this summary')
    parser.add_argument('--min-severity', choices=LEVELS, default='high')
    parser.add_argument('--days', type=float, default=3)
    parser.add_argument('--history', action='store_true', help='Remove time filter')
    parser.add_argument('--dedup-history', type=Path, default=ROOT / 'history.json')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--all', action='store_true', help='Ignore history; do not update it')
    mode.add_argument('--shown', action='store_true', help='Only previously shown; do not update history')


def build_parser():
    parser = argparse.ArgumentParser(description='Collect and inspect product security advisories')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('update', 'summary', 'detail'):
        sub = commands.add_parser(name)
        common(sub)
        if name == 'update':
            update_options(sub)
        elif name == 'summary':
            summary_options(sub)
        else:
            sub.add_argument('--severity', choices=LEVELS, required=True)
            detail_options(sub)
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    validate(parser, args)
    try:
        with locked(args):
            return {'update': update.run, 'summary': views.summary, 'detail': views.detail}[args.command](args)
    except Exception as exc:
        logging.getLogger(__name__).error(f'{exc}')
        return 2


def detail_options(parser):
    period = parser.add_mutually_exclusive_group()
    period.add_argument('--days', type=float, default=3, help='Published or updated within N days (default: 3)')
    period.add_argument('--since', type=parse_time, help='Published or updated since ISO timestamp (UTC if no zone)')
    period.add_argument('--history', action='store_true', help='Remove time filter')
