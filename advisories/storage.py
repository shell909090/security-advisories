"""JSON persistence and selected product configuration."""
import json


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


def load_state(path):
    state = read_json(path, {'version': 1, 'units': {}})
    if state.get('version') != 1:
        raise ValueError('Unsupported state version')
    return state


def emit(text, output):
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8')
    elif text:
        print(text, end='', flush=True)
