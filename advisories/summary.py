"""Product-oriented Markdown summary without per-vulnerability IDs or scores."""
from collections import Counter
from .evidence import is_kev
from .impact import CONSEQUENCES, impact_tags
from .version_summary import summarize


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def render_group(product, rows):
    counts = Counter('kev' if is_kev(row) else row['severity'] for row in rows)
    affected, fixed = summarize(rows, product)
    tags = sorted({tag for row in rows for tag in impact_tags(row)})
    values = [product.get('label', product['id']), counts['kev'], counts['critical'], counts['high'],
              affected, fixed, ', '.join(tags) or '未知/待核实']
    return '| ' + ' | '.join(cell(value) for value in values) + ' |'


def render_list_group(product, rows):
    counts = Counter('kev' if is_kev(row) else row['severity'] for row in rows)
    affected, fixed = summarize(rows, product)
    tags = sorted({tag for row in rows for tag in impact_tags(row)})
    consequences = '、'.join(CONSEQUENCES[tag] for tag in tags if tag in CONSEQUENCES) or '未知'
    lines = ['## ' + product.get('label', product['id']),
             f"- KEV: {counts['kev']} / Critical: {counts['critical']} / High: {counts['high']}",
             f'- 受影响版本：{affected}', f'- 公告修复版本：{fixed}', f'- 后果：{consequences}']
    return '\n'.join(str(line).replace('\n', ' ').replace('\r', ' ') for line in lines) + '\n\n'


def render(selected, list_mode=False):
    if not selected:
        return ''
    groups = {}
    for product, row in selected:
        groups.setdefault(product['id'], (product, []))[1].append(row)
    if list_mode:
        return ''.join(render_list_group(*groups[key]) for key in sorted(groups))
    lines = ['| 产品 | KEV | Critical | High | 受影响版本/组件 | 公告修复版本 | 证据标签 |',
             '| --- | ---: | ---: | ---: | --- | --- | --- |']
    lines.extend(render_group(*groups[key]) for key in sorted(groups))
    return '\n'.join(lines) + '\n'
