"""Split the state into independently writable JSON documents."""
import json


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def split_node(path):
    if not path:
        return True
    if path[0] not in ('units', 'catalog', 'source_caches'):
        return False
    if len(path) <= 2:
        return True
    fields = {'units': ('records', 'cve_seen', 'known_checked_at'),
              'catalog': ('records',), 'source_caches': ('details', 'indexes')}
    return len(path) == 3 and path[2] in fields[path[0]]


def nodes(value, path=()):
    if split_node(path) and isinstance(value, (dict, list)):
        kind = 'dict' if isinstance(value, dict) else 'list'
        keys = list(value) if kind == 'dict' else list(range(len(value)))
        yield encode(path), kind, encode(keys)
        for key in keys:
            yield from nodes(value[key], (*path, key))
    else:
        yield encode(path), 'value', encode(value)


def node(connection, path):
    row = connection.execute('SELECT kind, json(body) FROM nodes WHERE path=?', (encode(path),)).fetchone()
    if row is None:
        raise ValueError('Missing SQLite state node')
    return row[0], json.loads(row[1])


def read_node(connection, path=()):
    kind, value = node(connection, path)
    if kind == 'value':
        return value
    if kind == 'dict':
        return {key: read_node(connection, (*path, key)) for key in value}
    if kind == 'list':
        return [read_node(connection, (*path, key)) for key in value]
    raise ValueError('Unknown SQLite state node kind')


def read_catalog(connection, products):
    _, keys = node(connection, ())
    state = {'version': read_node(connection, ('version',)), 'units': {}}
    if 'catalog' in keys:
        _, available = node(connection, ('catalog',))
        state['catalog'] = {key: read_node(connection, ('catalog', key))
                            for key in products if key in available}
    return state
