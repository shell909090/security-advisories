"""Repository advisory watermarks with periodic complete reconciliation."""
import datetime as dt
from .source_common import parse_time, stamp


def due_full(old, until, changed=False):
    previous = old.get('full_checked_at')
    if changed or not previous:
        return True
    return until - parse_time(previous) >= dt.timedelta(days=7)


def older_than(advisory, since):
    if since is None:
        return False
    # Never early-stop on publication time: an older advisory may have changed.
    try:
        return parse_time(advisory['updated_at']) < parse_time(str(since))
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def collect_project(fetch, client, product, since, until, context):
    old = context.get('old', {})
    full = since is None or due_full(old, until, context.get('config_changed', False))
    records = list(fetch(client, product, None if full else since, until))
    checked = stamp(until) if full else old['full_checked_at']
    return {'records': records, 'metadata': {'full_checked_at': checked}, 'replace_records': full}
