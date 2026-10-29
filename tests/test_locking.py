"""All commands share one nonblocking interprocess lock, released on failure."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from advisories.locking import locked, lock_path
from advisories.cli import build_parser
from advisories.validation import validate
from unittest.mock import patch

CHILD = '''
import sys
from pathlib import Path
from types import SimpleNamespace
from advisories.locking import locked
try:
    with locked(SimpleNamespace(state=Path(sys.argv[1]), command=sys.argv[2])):
        pass
except RuntimeError:
    sys.exit(7)
'''


class LockTests(unittest.TestCase):
    def test_commands_and_different_state_names_share_one_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            with locked(SimpleNamespace(state=state)):
                for command in ('update', 'summary', 'detail'):
                    result = subprocess.run([sys.executable, '-c', CHILD,
                                             str(state.with_name('other.json')), command], timeout=5)
                    self.assertEqual(result.returncode, 7)
            result = subprocess.run([sys.executable, '-c', CHILD, str(state), 'summary'], timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(list(Path(directory).iterdir()), [lock_path(state)])

    def test_exception_releases_lock_and_separate_directories_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(state=Path(directory) / 'state.json')
            with self.assertRaises(ValueError):
                with locked(args):
                    with locked(SimpleNamespace(state=Path(directory) / 'other' / 'state.json')):
                        raise ValueError('failed command')
            with locked(args):
                self.assertTrue(lock_path(args.state).exists())

    def test_output_cannot_replace_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            parser = build_parser()
            args = parser.parse_args(['summary', '--state', str(state), '--output', str(lock_path(state))])
            with self.assertRaises(SystemExit), patch('sys.stderr'):
                validate(parser, args)
