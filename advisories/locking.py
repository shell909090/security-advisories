"""Coordinate update and display processes sharing state/history files."""
import contextlib
import fcntl


@contextlib.contextmanager
def locked(args):
    paths = [args.state]
    if args.command == 'summary' and not args.all:
        paths.append(args.dedup_history)
    with contextlib.ExitStack() as stack:
        for path in sorted(set(paths)):
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = stack.enter_context(path.with_suffix(path.suffix + '.lock').open('a'))
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Another process is using this state/history') from None
        yield
