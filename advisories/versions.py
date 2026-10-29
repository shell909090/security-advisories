"""Evidence-preserving version extraction; no cross-branch version arithmetic."""
import re


def version_nodes(value, context=''):
    if isinstance(value, dict):
        context = ' / '.join(filter(None, [context, label(value)]))
        yield value, context
        for child in value.values():
            yield from version_nodes(child, context)
    elif isinstance(value, list):
        for child in value:
            yield from version_nodes(child, context)


def label(node):
    package = node.get('package') or {}
    name = package.get('name') or node.get('product') or node.get('name') or ''
    platforms = ', '.join(str(p) for p in node.get('platforms', []))
    return ' / '.join(filter(None, [name, platforms]))


def cve_ranges(node):
    result = []
    for version in node.get('versions', []):
        if not isinstance(version, dict) or version.get('status') != 'affected':
            continue
        start = version.get('version', '?')
        upper = version.get('lessThan')
        inclusive = version.get('lessThanOrEqual')
        bounds = f'>= {start}' if start not in ('0', '*') else '*'
        if upper:
            bounds += f', < {upper}'
        elif inclusive:
            bounds += f', <= {inclusive}'
        else:
            bounds = str(start)
        # Some CNA records repeat the exclusive upper bound as version.
        if upper == start:
            bounds = f'< {upper}'
        result.append((bounds, '未知', label(node)))
    return result


def osv_ranges(node):
    result = []
    start = '未知'
    for event in node.get('events', []):
        if 'introduced' in event:
            start = str(event['introduced'])
        elif 'fixed' in event:
            result.append((f'>= {start}, < {event["fixed"]}', str(event['fixed']), node.get('type', '')))
            start = '未知'
        elif 'last_affected' in event:
            result.append((f'>= {start}, <= {event["last_affected"]}', '未知', node.get('type', '')))
            start = '未知'
    if start != '未知':
        result.append((f'>= {start}（未提供修复边界）', '未知', node.get('type', '')))
    return result


def cpe_range(node):
    if not node.get('vulnerable'):
        return []
    bounds = []
    for key, operator in [('versionStartIncluding', '>='), ('versionStartExcluding', '>'),
                          ('versionEndIncluding', '<='), ('versionEndExcluding', '<')]:
        if key in node:
            bounds.append(f'{operator} {node[key]}')
    return [(', '.join(bounds) or node.get('criteria', '未知'), '未知', node.get('criteria', ''))]


def node_versions(node):
    result = cve_ranges(node) + osv_ranges(node) + cpe_range(node)
    if node.get('vulnerable_version_range'):
        fixed = node.get('first_patched_version') or node.get('patched_versions') or '未知'
        if isinstance(fixed, dict):
            fixed = fixed.get('identifier', '未知')
        result.append((str(node['vulnerable_version_range']), str(fixed), label(node)))
    return result


def evidence_versions(evidence):
    result = []
    for node, context in version_nodes(evidence.get('affected', [])):
        for span, fixed, component in node_versions(node):
            result.append((span, fixed, context or component))
    text = evidence.get('description') or ''
    # This explicit product/version sentence states the Chrome fix boundary.
    for match in re.finditer(r'Google Chrome(?: on [^\n]*?)? prior to (\d+\.\d+\.\d+\.\d+)', text):
        version = match.group(1)
        result.append((f'< {version}', version, 'Chrome（公告正文）'))
    return result


def version_facts(row):
    facts = set()
    for evidence in row['evidence']:
        for affected, fixed, component in evidence_versions(evidence):
            facts.add((affected, fixed, component, evidence.get('source', 'unknown')))
    return sorted(facts)
