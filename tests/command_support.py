"""Isolated command fixtures; never use the user's state or display history."""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
from advisories.cli import main


def setup(root):
    products = [dict(id=name, label=name.upper(), packages=[{'ecosystem': 'npm', 'name': name}],
                     repositories=['org/' + name], keywords=[name]) for name in ('one', 'two')]
    (root / 'products.json').write_text(json.dumps(products))


def command(root, name, *extra):
    args = [name, '--products', str(root / 'products.json'), '--state', str(root / 'state.json')]
    if name == 'summary':
        args += ['--dedup-history', str(root / 'history.json')]
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(args + list(extra))
    return code, stdout.getvalue(), stderr.getvalue()


def record(ident='GHSA-test', product='one', severity='critical', date=None):
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    return dict(id=ident, aliases=[], products=[product], severity=severity,
                title='Remote code execution', description='A remote attacker can execute arbitrary code.',
                published=date or now, modified=date or now, kind='vulnerability', withdrawn=False,
                scores=[], affected=[{'package': {'name': product}, 'vulnerable_version_range': '< 2.0',
                                      'first_patched_version': '2.0'}])


def catalog(root, rows):
    from advisories.records import merge_records
    merged = merge_records({'ghsa:one': {'records': {r['id']: r for r in rows}}})
    data = {p: {'records': [r for r in merged if p in r['products']], 'min_severity': 'high'}
            for p in ('one', 'two')}
    (root / 'state.json').write_text(json.dumps({'version': 1, 'units': {}, 'catalog': data}))
    return merged
