"""JSON persistence and selected product configuration."""
import json
from .cache_storage import load_cache, save_cache
from .sqlite_storage import is_sqlite, load_sqlite, save_sqlite
from .inspection_storage import pack, unpack, transform_state


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.new')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def read_json(path, default):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default


def load_products(args):
    products = json.loads(args.products.read_text(encoding='utf-8'))
    if not products or any(not p.get('id') or not isinstance(p.get('packages'), list) for p in products):
        raise ValueError('Invalid products configuration')
    selected = set(args.product.split(',')) if args.product else {p['id'] for p in products}
    unknown = selected - {p['id'] for p in products}
    if unknown:
        raise ValueError('Unknown product: ' + ', '.join(sorted(unknown)))
    return [p for p in products if p['id'] in selected]


def load_state(path, with_http=False, products=None):
    state = load_sqlite(path, products) if is_sqlite(path) else read_json(path, {'version': 1, 'units': {}})
    if state.get('version') != 1:
        raise ValueError('Unsupported state version')
    inline = state.pop('http_cache', None)
    if with_http:
        state['http_cache'] = inline if inline is not None else load_cache(path)
    return transform_state(state, unpack)


def emit(text, output):
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8')
    elif text:
        print(text, end='', flush=True)


def save_state(path, state):
    packed = transform_state(state, pack)
    entries = packed.pop('http_cache', None)
    if entries is not None:
        save_cache(path, entries)
    if is_sqlite(path):
        save_sqlite(path, packed)
    else:
        atomic_json(path, packed)
