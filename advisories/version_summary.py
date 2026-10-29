"""Product-scoped version labels for compact summaries; full evidence stays in detail."""
import re
from .versions import version_facts
from .version_ranges import merge_spans, version


def component_label(component, product):
    if component.startswith('cpe:'):
        parts = component.split(':')
        platform = parts[10] if len(parts) > 10 else '*'
        return product['id'] + (f' ({platform})' if platform not in ('*', '-') else '')
    return component.replace('（公告正文）', '') or product['id']


def facts_for_product(row, product):
    result = set()
    for span, fixed, component, _ in version_facts(row, product):
        label = component_label(component, product)
        if label is None:
            continue
        span = re.sub(r'([<>=]+)\s*', r'\1 ', span)
        result.add((span, fixed, label.casefold()))
    return result


def summarize(rows, product):
    affected, fixed = {}, {}
    missing = 0
    for row in rows:
        facts = facts_for_product(row, product)
        for span, _, component in facts:
            affected.setdefault(component, set()).add(span)
        for _, fix, component in facts:
            if fix != '未知':
                fixed.setdefault(component, set()).add(fix)
        missing += not any(fix != '未知' for _, fix, _ in facts)
    fixes = render_groups(fixed, product['id'].casefold() == 'chrome')
    if missing:
        fixes += f'；{missing} 条未提供明确修复版本，不能保证全部修复'
    return render_groups(affected), fixes


def render_groups(groups, cumulative=False):
    labels = [f'{component}: {span}' for component, spans in sorted(groups.items())
              for span in (merge_fixes(spans) if cumulative else merge_spans(spans))]
    return '; '.join(labels) or '未知/待核实'


def merge_fixes(spans):
    """Chrome stable releases accumulate fixes; opaque branch expressions stay separate."""
    numeric = {span for span in spans if re.fullmatch(r'\d+(?:\.\d+)*', span)}
    remaining = set(spans) - numeric
    if numeric:
        remaining.add(max(numeric, key=lambda text: (version(text), len(text), text)))
    return merge_spans(remaining)
