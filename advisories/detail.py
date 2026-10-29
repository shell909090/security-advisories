"""Read-only Markdown evidence for all vulnerabilities at an exact severity."""
import json
from .impact import impact_tags
from .reporting import compact
from .summary import cell
from .versions import version_facts


def render_evidence(evidence):
    lines = [f"### 来源：{cell(evidence.get('source', 'unknown'))}", '',
             f"发布时间：{cell(evidence.get('published') or '未知')}；"
             f"更新时间：{cell(evidence.get('modified') or '未知')}", '',
             f"来源状态：{'已撤回（不参与汇总）' if evidence.get('withdrawn') else '有效'}", '',
             f"来源等级：{cell(evidence.get('severity', 'unknown'))}", '',
             '评分：' + cell(json.dumps(evidence.get('scores', []), ensure_ascii=False)), '',
             '原始链接：' + cell(evidence.get('url') or '未知'), '']
    lines.extend('> ' + line for line in (evidence.get('description') or '无正文').splitlines())
    lines.extend(['', '受影响范围原始证据：', ''])
    lines.extend('> ' + line for line in json.dumps(evidence.get('affected', []), ensure_ascii=False, indent=2).splitlines())
    return lines + ['']


def render_row(index, row):
    compacted = compact(row, 'detail')
    lines = [f"## {index}. {cell(row['id'])} — {cell(compacted['title'])}", '',
             '编号/别名：' + ', '.join(row['aliases']), '',
             f"汇总等级：{row['severity']}（未撤回来源最高值，可能与厂商评级不同）", '',
             '证据标签：' + (', '.join(impact_tags(row)) or '未知/待核实'), '',
             '| 组件/平台 | 受影响范围 | 修复版本 | 来源 |', '| --- | --- | --- | --- |']
    facts = version_facts(row) or [('未知', '未知', '未知', '未知')]
    lines.extend('| ' + ' | '.join(cell(v) for v in (component, span, fix, source)) + ' |'
                 for span, fix, component, source in facts)
    lines.append('')
    for evidence in row['evidence']:
        lines.extend(render_evidence(evidence))
    return lines


def render(product, severity, rows, period='全部历史'):
    lines = [f"# {cell(product)} / {severity}：{len(rows)} 个漏洞", '',
             f'时间范围：{period}（按发布时间或更新时间）；不受展示历史限制。', '']
    for index, row in enumerate(rows, 1):
        lines.extend(render_row(index, row))
    return '\n'.join(lines) + '\n'
