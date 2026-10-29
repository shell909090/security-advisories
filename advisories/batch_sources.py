"""Shared preparation for batched sources while retaining per-product units."""
from .checkpoints import identity, window


def contexts(source, products, state, args, until):
    result = {}
    for product in products:
        key = source + ':' + product['id']
        old = state['units'].get(key, {})
        fingerprint = identity(source, product)
        since, changed = window(args, old, fingerprint, until)
        result[product['id']] = {'product': product, 'old': old, 'since': since,
                                 'config_changed': changed, 'collection_hash': fingerprint}
    return result


def package_key(package):
    return package['ecosystem'] + ':' + package['name']


def package_targets(contexts):
    targets = {}
    for ident, context in contexts.items():
        for package in context['product']['packages']:
            target = targets.setdefault(package_key(package), {'package': package, 'products': []})
            if ident not in target['products']:
                target['products'].append(ident)
    return targets
