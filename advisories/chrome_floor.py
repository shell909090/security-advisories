"""Interpret Chrome CNA's repeated upper boundary only with matching prose."""
import re


def corroborated_node(node, evidence, product):
    if product['id'].casefold() != 'chrome':
        return node
    if str(node.get('vendor', '')).casefold() != 'google':
        return node
    if str(node.get('product', '')).casefold() not in ('chrome', 'google chrome'):
        return node
    boundaries = prose_boundaries(evidence, product)
    versions = [normalize_entry(entry, boundaries) for entry in node.get('versions', [])]
    return dict(node, versions=versions)


def normalize_entry(entry, boundaries):
    if not isinstance(entry, dict) or entry.get('versionType') != 'custom':
        return entry
    boundary = entry.get('version')
    if not isinstance(boundary, str) or boundary not in boundaries:
        return entry
    if entry.get('lessThan') != boundary or 'lessThanOrEqual' in entry:
        return entry
    return dict(entry, version='0', versionType='semver')


def prose_boundaries(evidence, product):
    if product['id'].casefold() != 'chrome':
        return set()
    return set(re.findall(
        r'Google Chrome(?: on [^\n]*?)? prior to (\d+\.\d+\.\d+\.\d+)(?![\w.])',
        evidence.get('description') or ''))
