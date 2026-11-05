"""Bound per-run NVD product work, prioritizing mandatory and oldest UTC dates."""
import datetime as dt
import logging
import random
from .checkpoints import identity
from .source_common import parse_time

FRESHNESS = dt.timedelta(days=3)


def eligible_day(args, product, old, until):
    if any(getattr(args, name, False) for name in ('nvd_full', 'since', 'history')):
        return None
    if old.get('collection_hash') != identity('nvd', product):
        return None
    try:
        checkpoint = parse_time(old.get('checkpoint'))
    except (TypeError, ValueError, AttributeError):
        return None
    if checkpoint is None:
        return None
    age = until - checkpoint
    if not dt.timedelta(0) <= age < FRESHNESS:
        return None
    return checkpoint.astimezone(dt.timezone.utc).date()


def choose_keys(jobs, args, until):
    chosen, groups = set(), {}
    for _, product, key, old in jobs:
        day = eligible_day(args, product, old, until)
        if day is None:
            chosen.add(key)
        else:
            groups.setdefault(day, []).append(key)
    remaining = (len(jobs) + 2) // 3 - len(chosen)
    for day in sorted(groups):
        if remaining <= 0:
            break
        group = groups[day]
        count = min(remaining, len(group))
        chosen.update(group if count == len(group) else random.sample(group, count))
        remaining -= count
    return chosen


def select_jobs(jobs, args, until):
    nvd = [job for job in jobs if job[0] == 'nvd']
    chosen = choose_keys(nvd, args, until)
    selected = []
    logger = logging.getLogger(__name__)
    for job in jobs:
        if job[0] == 'nvd' and job[2] not in chosen:
            logger.info('Skipping %s: outside this run\'s oldest-date quota', job[2])
        else:
            selected.append(job)
    if nvd:
        logger.info('NVD plan: %s selected, %s skipped, %s total products (target %s)',
                    len(chosen), len(nvd) - len(chosen), len(nvd), (len(nvd) + 2) // 3)
    return selected
