"""Intern repeated CVE inspection scopes on disk; keep runtime mappings unchanged."""


def pack(container, key):
    if key not in container:
        return dict(container)
    scopes, references, entries = {}, {}, {}
    for ident, entry in container[key].items():
        if not isinstance(entry, dict):
            entries[ident] = entry
            continue
        products = entry.get('products', {})
        signature = tuple(sorted(products.items()))
        if signature not in references:
            reference = str(len(references))
            references[signature] = reference
            scopes[reference] = dict(products)
        saved = {k: v for k, v in entry.items() if k != 'products'}
        entries[ident] = dict(saved, products_ref=references[signature])
    return {**container, key: entries, key + '_scopes': scopes}


def unpack(container, key):
    if key not in container:
        return dict(container)
    scopes = container.get(key + '_scopes', {})
    entries = {ident: expand(entry, scopes) for ident, entry in container[key].items()}
    result = {k: v for k, v in container.items() if k != key + '_scopes'}
    return {**result, key: entries}


def expand(entry, scopes):
    if not isinstance(entry, dict) or 'products_ref' not in entry:
        return entry
    reference = entry['products_ref']
    if not isinstance(reference, str) or reference not in scopes:
        raise ValueError('Invalid CVE inspection scope reference')
    products = scopes[reference]
    if not isinstance(products, dict) or any(not isinstance(v, str) for v in products.values()):
        raise ValueError('Invalid CVE inspection scope mapping')
    if 'products' in entry:
        raise ValueError('Ambiguous CVE inspection scope')
    return {**{k: v for k, v in entry.items() if k != 'products_ref'}, 'products': products}


def transform_state(state, operation):
    units = dict(state.get('units', {}))
    if 'cve' in units:
        units['cve'] = operation(units['cve'], 'cve_seen')
    return {**state, 'units': units}
