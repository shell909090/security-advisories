"""Registry-specific package comparison, without substring matching."""
import re


def package_identity(ecosystem, name):
    if ecosystem in ('pip', 'PyPI'):
        return re.sub(r'[-_.]+', '-', name).lower()
    if ecosystem in ('rust', 'crates.io'):
        return name.lower().replace('_', '-')
    return name
