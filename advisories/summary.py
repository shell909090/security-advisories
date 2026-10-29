"""Product-oriented Markdown summary without per-vulnerability IDs or scores."""
from collections import Counter
from .impact import impact_tags
from .version_summary import summarize


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def render_group(product, rows):
    counts = Counter(row['severity'] for row in rows)
    affected, fixed = summarize(rows, product)
    tags = sorted({tag for row in rows for tag in impact_tags(row)})
    values = [product.get('label', product['id']), counts['critical'], counts['high'],
              affected, fixed, ', '.join(tags) or '未知/待核实']
    return '| ' + ' | '.join(cell(value) for value in values) + ' |'


def render(selected):
    if not selected:
        return ''
    groups = {}
    for product, row in selected:
        groups.setdefault(product['id'], (product, []))[1].append(row)
    lines = ['# 产品漏洞摘要', '',
             '计数为本次筛选后展示的活跃漏洞。标签来自公告措辞，包含后果和缺陷类型；未使用 AI 推断。', '',
             '| 产品 | Critical | High | 受影响版本/组件 | 公告修复版本 | 证据标签 |',
             '| --- | ---: | ---: | --- | --- | --- |']
    lines.extend(render_group(*groups[key]) for key in sorted(groups))
    return '\n'.join(lines) + '\n'
