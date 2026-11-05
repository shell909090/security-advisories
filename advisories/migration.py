"""Non-destructive, offline JSON-to-SQLite conversion under the directory lock."""
import shutil
from pathlib import Path
from .sqlite_storage import is_sqlite, save_sqlite, load_sqlite, integrity_check
from .storage import read_json


def progress_path(path):
    return Path(str(path) + '.cve-progress.json')


def validate_paths(source, destination):
    if not destination or not is_sqlite(destination):
        raise ValueError('Migration requires --output ending in .sqlite or .db')
    if is_sqlite(source) or not source.is_file():
        raise ValueError('Migration requires an existing JSON source')
    if source.resolve().parent != destination.resolve().parent:
        raise ValueError('Migration source and destination must share a directory')
    protected = [destination, progress_path(destination)]
    protected.extend(Path(str(destination) + suffix) for suffix in ('-journal', '-wal', '-shm'))
    if any(path.exists() or path.is_symlink() for path in protected):
        raise ValueError('Migration destination or auxiliary file already exists')


def convert(source, destination):
    validate_paths(source, destination)
    state = read_json(source, None)
    if state.get('version') != 1 or not isinstance(state.get('units'), dict):
        raise ValueError('Unsupported state version or units')
    created = []
    try:
        with destination.open('xb'):
            created.append(destination)
        save_sqlite(destination, state)
        integrity_check(destination)
        if load_sqlite(destination) != state:
            raise ValueError('Migrated state differs from source')
        if progress_path(source).exists():
            with progress_path(source).open('rb') as original, progress_path(destination).open('xb') as target:
                created.append(progress_path(destination))
                shutil.copyfileobj(original, target)
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def run(args):
    convert(args.state, args.output)
    before, after = args.state.stat().st_size, args.output.stat().st_size
    print(f'Migrated {args.state} -> {args.output}: {before} -> {after} bytes; source preserved')
    return 0
