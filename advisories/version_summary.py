"""Product-scoped version labels for compact summaries; full evidence stays in detail."""
import re
from .product_identity import normalize
from .versions import version_facts


def component_label(component, product):
    if component.startswith('cpe:'):
        parts = component.split(':')
        names = product.get('keywords', []) + [product.get('label', ''), product['id']]
        if normalize(parts[4]) not in {normalize(name) for name in names}:
            return None
        platform = parts[10] if len(parts) > 10 else '*'
        return product['id'] + (f' ({platform})' if platform not in ('*', '-') else '')
    return component.replace('（公告正文）', '') or product['id']


def facts_for_product(row, product):
    result = set()
    for span, fixed, component, _ in version_facts(row):
        label = component_label(component, product)
        if label is None:
            continue
        span = re.sub(r'([<>=]+)\s*', r'\1 ', span)
        result.add((span, fixed, label))
    return result


def summarize(rows, product):
    affected, fixed = set(), set()
    missing = 0
    for row in rows:
        facts = facts_for_product(row, product)
        affected.update(f'{component}: {span}' for span, _, component in facts)
        fixed.update(f'{component}: {fix}' for _, fix, component in facts if fix != '未知')
        missing += not any(fix != '未知' for _, fix, _ in facts)
    fixes = '; '.join(sorted(fixed)) or '未知/待核实'
    if missing:
        fixes += f'；{missing} 条未提供明确修复版本，不能保证全部修复'
    return '; '.join(sorted(affected)) or '未知/待核实', fixes
