"""Hide only evidence whose complete numeric affected ranges precede a floor."""
import re
from .evidence import active_evidence
from .version_ranges import parse_interval, version
from .version_scope import ownership
from .versions import version_nodes
from .floor_ranges import structured_spans
from .chrome_floor import corroborated_node, prose_boundaries


def minimum(product):
    value = product.get('min_version')
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:\.\d+)*', value):
        raise ValueError(f"{product['id']}: min_version must be a dotted numeric string")
    return version(value)


def below(span, floor):
    intervals = [parse_interval(part) for part in span.split('||')]
    if not intervals or not all(intervals):
        return False
    return all(high[0] < floor or (high[0] == floor and not high[1])
               for _, high in intervals)


def evidence_below(evidence, product, floor):
    affected = evidence.get('affected', [])
    if any(node.get('negate') for node, _ in version_nodes(affected)):
        return False
    nodes = [node for node, _ in version_nodes(affected, product=product)
             if ownership(node, product) is True]
    if not nodes:
        return prose_only_below(affected, evidence, product, floor)
    return all(node_below(corroborated_node(node, evidence, product), floor) for node in nodes)


def node_below(node, floor):
    spans = structured_spans(node)
    return bool(spans) and all(below(span, floor) for span in spans)


def excluded(row, product):
    floor = minimum(product)
    if floor is None:
        return False
    evidence = list(active_evidence(row))
    return bool(evidence) and all(evidence_below(item, product, floor) for item in evidence)


def prose_only_below(affected, evidence, product, floor):
    if any(node for node, _ in version_nodes(affected)):
        return False
    boundaries = prose_boundaries(evidence, product)
    return bool(boundaries) and all(below('< ' + bound, floor) for bound in boundaries)
