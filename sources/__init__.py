"""Discover source plugins. Each defines NAME, GLOBAL and collect()."""
import importlib
import pkgutil
import re


def discover():
    result = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda item: item.name):
        if info.name.startswith('_'):
            continue
        module = importlib.import_module(f'{__name__}.{info.name}')
        name = getattr(module, 'NAME', None)
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9_-]*', name):
            raise ValueError(f'Invalid source NAME: {info.name}')
        if name in result:
            raise ValueError(f'Duplicate source NAME: {name}')
        if not isinstance(getattr(module, 'GLOBAL', None), bool) or not callable(getattr(module, 'collect', None)):
            raise ValueError(f'Invalid source protocol: {name}')
        result[name] = module
    return result
