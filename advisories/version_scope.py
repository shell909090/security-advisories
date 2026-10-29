"""Resolve structured version ownership before flattening component labels."""
from .package_names import package_identity
from .product_identity import normalize, cpe_matches

ALIASES = {'pip': 'PyPI', 'go': 'Go', 'rust': 'crates.io'}


def names(product):
    return {normalize(name) for name in [product['id'], product.get('label', ''),
            *product.get('keywords', []), *(p['name'] for p in product.get('packages', []))] if name}


def vendors(product):
    return {normalize(v) for v in product.get('vendor_aliases', product.get('vendors', []))}


def package_matches(package, product):
    ecosystem = ALIASES.get(package.get('ecosystem'), package.get('ecosystem'))
    configured = product.get('packages', [])
    if not configured:
        return not ecosystem and normalize(package.get('name', '')) in names(product)
    for target in configured:
        expected = ALIASES.get(target.get('ecosystem'), target.get('ecosystem'))
        if ecosystem and ecosystem != expected:
            continue
        if package_identity(expected, package.get('name', '')) == package_identity(expected, target['name']):
            return True
    return False


def ownership(node, product):
    """None means a structural/component node that inherits its parent's scope."""
    if node.get('package'):
        return package_matches(node['package'], product)
    if node.get('criteria') or node.get('cpe23Uri'):
        return node.get('vulnerable') is not False and cpe_matches(
            node.get('criteria') or node['cpe23Uri'], names(product), vendors(product))
    if node.get('product'):
        allowed = vendors(product)
        if allowed and node.get('vendor') and normalize(node['vendor']) not in allowed:
            return False
        return any(normalize(name) in names(product) for name in
                   (node['product'], node.get('vendor', '') + ' ' + node['product']))
    return None
