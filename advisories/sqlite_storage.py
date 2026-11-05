"""Transactional SQLite JSONB state storage; callers hold the data-directory lock."""
import contextlib
import logging
import sqlite3
from .sqlite_nodes import nodes, read_node, read_catalog

APPLICATION_ID = 1396786244
SCHEMA = '''CREATE TABLE nodes (
    path TEXT PRIMARY KEY, kind TEXT NOT NULL, body BLOB NOT NULL
)'''
UPSERT = '''INSERT INTO nodes VALUES (?, ?, jsonb(?))
    ON CONFLICT(path) DO UPDATE SET kind=excluded.kind, body=excluded.body
    WHERE nodes.kind != excluded.kind OR nodes.body != excluded.body'''


def is_sqlite(path):
    return path.suffix.lower() in ('.sqlite', '.db')


def check_version(connection):
    try:
        connection.execute("SELECT jsonb('{}')").fetchone()
    except sqlite3.OperationalError:
        raise RuntimeError('SQLite >= 3.45 with JSONB support is required') from None


@contextlib.contextmanager
def connect(path, writable=False):
    mode = 'rwc' if writable else 'ro'
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=' + mode, uri=True)
    try:
        check_version(connection)
        yield connection
    finally:
        connection.close()


def validate_database(connection):
    app = connection.execute('PRAGMA application_id').fetchone()[0]
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    if (app, version) != (APPLICATION_ID, 1):
        raise ValueError('Unsupported SQLite state format')


def initialize(connection):
    app = connection.execute('PRAGMA application_id').fetchone()[0]
    tables = connection.execute('SELECT name FROM sqlite_master').fetchone()
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    if app == 0 and version == 0 and tables is None:
        connection.execute(SCHEMA)
        connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
        connection.execute('PRAGMA user_version=1')
    validate_database(connection)


def load_sqlite(path, products=None):
    if not path.exists():
        return {'version': 1, 'units': {}}
    with connect(path) as connection:
        validate_database(connection)
        return read_node(connection) if products is None else read_catalog(connection, products)


def write_nodes(connection, state):
    connection.execute('CREATE TEMP TABLE live (path TEXT PRIMARY KEY) WITHOUT ROWID')
    for path, kind, body in nodes(state):
        connection.execute(UPSERT, (path, kind, body))
        connection.execute('INSERT INTO live VALUES (?)', (path,))
    connection.execute('DELETE FROM nodes WHERE path NOT IN (SELECT path FROM live)')


def save_sqlite(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path, writable=True) as connection:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            initialize(connection)
            write_nodes(connection, state)
        vacuum(connection)


def integrity_check(path):
    with connect(path) as connection:
        if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('SQLite integrity check failed')


def vacuum(connection):
    try:
        connection.execute('VACUUM')
    except sqlite3.Error as exc:
        logging.getLogger(__name__).warning('State saved, but SQLite VACUUM failed: %s', exc)
