"""Serialize all commands with one lock per data directory."""
import contextlib
import fcntl


def lock_path(state_path):
    return state_path.resolve().parent / 'advisories.lock'


@contextlib.contextmanager
def locked(args):
    path = lock_path(args.state)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another command is using this data directory') from None
        yield
