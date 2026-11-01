"""Strict structured ranges for filtering, independent of display heuristics."""
from .versions import cpe_range


def structured_spans(node):
    if 'vulnerable_version_range' in node:
        value = node['vulnerable_version_range']
        return [value] if isinstance(value, str) else []
    if 'package' in node:
        return osv_spans(node)
    if 'product' in node:
        return cve_spans(node)
    if node.get('vulnerable') is True:
        return [span for span, _, _ in cpe_range(node)]
    return []


def osv_spans(node):
    spans = []
    for value in node.get('versions', []):
        if not isinstance(value, str):
            return []
        spans.append(value)
    for item in node.get('ranges', []):
        if item.get('type') not in ('SEMVER', 'ECOSYSTEM'):
            return []
        ranges = event_spans(item.get('events', []))
        if not ranges:
            return []
        spans.extend(ranges)
    return spans


def event_spans(events):
    spans, start = [], None
    if not all(valid_event(event) for event in events):
        return []
    for event in events:
        key, value = next(iter(event.items()))
        if key == 'introduced':
            if start is not None:
                return []
            start = value
        elif key in ('fixed', 'last_affected', 'limit') and start is not None:
            operator = '<=' if key == 'last_affected' else '<'
            spans.append(f'>= {start}, {operator} {value}')
            start = None
        else:
            return []
    if start is not None:
        spans.append(f'>= {start}')
    return spans


def cve_spans(node):
    if node.get('defaultStatus') not in (None, 'unaffected'):
        return []
    spans = []
    for item in node.get('versions', []):
        span = cve_span(item)
        if span is None:
            return []
        if span:
            spans.append(span)
    # Component subtrees need their own interpretation, not just parent ranges.
    if node.get('components'):
        return []
    return spans


def cve_span(item):
    if not isinstance(item, dict) or item.get('changes'):
        return None
    if item.get('versionType') not in (None, 'semver', 'python'):
        return None
    if item.get('status') == 'unaffected':
        return ''
    if item.get('status') != 'affected':
        return None
    start = item.get('version')
    if not isinstance(start, str):
        return None
    lower = '>= 0' if start == '*' else f'>= {start}'
    if 'lessThan' in item:
        return f'{lower}, < {item["lessThan"]}'
    if 'lessThanOrEqual' in item:
        return f'{lower}, <= {item["lessThanOrEqual"]}'
    return start


def valid_event(event):
    return (isinstance(event, dict) and len(event) == 1
            and isinstance(next(iter(event.values())), str))
