"""Optional compressed HTTP cache, independent of authoritative collection state."""
import gzip
import json
import logging
import zlib
from pathlib import Path


def cache_path(state_path):
    return Path(state_path).parent / 'http-cache.json.gz'


def load_cache(state_path):
    path = cache_path(state_path)
    if not path.exists():
        path = Path(str(state_path) + '.http-cache.json.gz')
    if not path.exists():
        return {}
    try:
        with gzip.open(path, 'rt', encoding='utf-8') as stream:
            data = json.load(stream)
        if data.get('version') != 1 or not isinstance(data.get('entries'), dict):
            raise ValueError('Unsupported HTTP cache format')
        for entry in data['entries'].values():
            validate_entry(entry)
        return data['entries']
    except (OSError, EOFError, ValueError, TypeError, AttributeError, zlib.error) as exc:
        logging.getLogger(__name__).warning('HTTP cache unreadable; refetching (%s)', type(exc).__name__)
        return {}


def validate_entry(entry):
    if not isinstance(entry, dict) or not {'body', 'source', 'used_at'} <= entry.keys():
        raise ValueError('Incomplete HTTP cache entry')
    if not isinstance(entry['used_at'], (int, float)):
        raise ValueError('Invalid HTTP cache access time')


def save_cache(state_path, entries):
    path = cache_path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.new')
    try:
        with gzip.open(temporary, 'wt', encoding='utf-8', compresslevel=6) as stream:
            json.dump({'version': 1, 'entries': entries}, stream, ensure_ascii=False, separators=(',', ':'))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
