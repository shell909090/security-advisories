"""Conservative interval algebra for dotted numeric versions only."""
import re

LOW = ((-1,), False)
HIGH = ((float('inf'),), False)


def version(text):
    parts = [int(part) for part in text.split('.')]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def lower_key(bound):
    return bound[0], not bound[1]


def upper_key(bound):
    return bound[0], bound[1]


def nonempty(low, high):
    return low[0] < high[0] or (low[0] == high[0] and low[1] and high[1])


def parse_interval(text):
    low, high = LOW, HIGH
    for clause in text.split(','):
        match = re.fullmatch(r'\s*(>=|<=|==|=|>|<)?\s*(\d+(?:\.\d+)*)\s*', clause)
        if not match:
            return None
        operator, number = match.groups()
        operator = operator or '='
        bound = (version(number), '=' in operator)
        if operator in ('>', '>=', '=', '=='):
            low = max(low, bound, key=lower_key)
        if operator in ('<', '<=', '=', '=='):
            high = min(high, bound, key=upper_key)
    return (low, high) if nonempty(low, high) else None


def render_interval(interval, names):
    low, high = interval
    if low[0] == high[0]:
        return names[low[0]]
    result = []
    for bound, sentinel, operator in [(low, LOW, '>'), (high, HIGH, '<')]:
        if bound != sentinel:
            result.append(operator + ('=' if bound[1] else '') + ' ' +
                          names[bound[0]])
    return ', '.join(result) or '*'


def union(intervals):
    result = []
    for low, high in sorted(intervals, key=lambda item: lower_key(item[0])):
        if not result or separated(result[-1][1], low):
            result.append((low, high))
        else:
            result[-1] = (result[-1][0], max(result[-1][1], high, key=upper_key))
    return result


def separated(high, low):
    return high[0] < low[0] or (high[0] == low[0] and not (high[1] or low[1]))


def merge_spans(spans):
    intervals, preserved, names = [], set(), {}
    for span in spans:
        parsed = [parse_interval(part) for part in span.split('||')]
        if all(parsed):
            intervals.extend(parsed)
            for number in re.findall(r'\d+(?:\.\d+)*', span):
                key = version(number)
                names[key] = max(names.get(key, number), number, key=len)
        else:
            preserved.add(span)
    return sorted(preserved | {render_interval(item, names) for item in union(intervals)})
