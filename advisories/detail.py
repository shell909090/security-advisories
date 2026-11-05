"""Concise offline vulnerability details; source evidence stays in the cache."""
import re
from .evidence import active_evidence
from .impact import CONSEQUENCES, impact_tags
from .summary import cell
from .versions import version_facts
from .version_summary import component_label
from .version_ranges import merge_spans



def readable_span(span):
    if span.startswith('cpe:2.3:'):
        parts = span.split(':')
        if len(parts) < 7 or parts[5] in ('*', '-'):
            return '未知'
        return parts[5] + (f' {parts[6]}' if parts[6] not in ('*', '-') else '')
    if re.match(r'^[A-Za-z]', span):
        return f'待核实（来源版本文本：{span}）'
    span = re.sub(r'^(?:\*|>= 0),\s*', '', span)
    match = re.fullmatch(r'>= (.+), (<|<=) (.+)', span)
    if match:
        lower, operator, upper = match.groups()
        return f'{lower} ≤ 版本 {"≤" if operator == "<=" else "<"} {upper}'
    return span.replace('<=', '≤').replace('>=', '≥')


def affected_versions(row, product=None):
    groups = {}
    for span, _, component, _ in version_facts(row, product):
        label = component_label(component, product or {'id': '产品'})
        groups.setdefault(label, set()).add(span)
    return '<br>'.join(f'{cell(component)}: {cell(readable_span(span))}'
                      for component, spans in sorted(groups.items())
                      for span in merge_spans(spans)) or '未知'


def render_row(index, row, product=None):
    consequences = '、'.join(CONSEQUENCES[tag] for tag in impact_tags(row)
                            if tag in CONSEQUENCES) or '未知'
    url = next((item['url'] for item in active_evidence(row) if item.get('url')), '未知')
    severity = row.get('severity') or 'unknown'
    level = '未知' if severity == 'unknown' else severity.capitalize()
    published = next((e['published'] for e in active_evidence(row)
                      if e.get('published') and e.get('source', '').split(':')[0] != 'kev'), '未知')
    values = [cell(row['id']), cell(level), cell(published), affected_versions(row, product), cell(consequences), cell(url)]
    return ['| ' + ' | '.join(values) + ' |']


def render_description(row):
    description = next((item['description'].strip() for item in active_evidence(row)
                        if (item.get('description') or '').strip()), '暂无原始描述')
    lines = [f"## {cell(row['id'])}", '']
    lines.extend('> ' + line for line in description.splitlines())
    return lines + ['']


def render(product, severity, rows, period='全部历史', config=None):
    lines = [f'# {cell(product)} / {severity}：{len(rows)} 个漏洞', '',
             f'时间范围：{period}（按发布时间或更新时间）', '']
    for row in rows:
        lines.extend(render_description(row))
    lines.extend(['## 总结', '', '| 漏洞 ID | 威胁级别 | 公告时间 | 受影响版本 | 后果 | 原始链接 |', '| --- | --- | --- | --- | --- | --- |'])
    for index, row in enumerate(rows, 1):
        lines.extend(render_row(index, row, config))
    return '\n'.join(lines) + '\n'
