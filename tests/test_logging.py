"""Check logging in a fresh process, independent of test runner handlers."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LoggingTests(unittest.TestCase):
    def test_error_only_on_stderr(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, str(root / 'main.py'), 'summary',
                 '--products', str(Path(temporary) / 'missing.json'),
                 '--state', str(Path(temporary) / 'state.json')],
                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertIn('ERROR advisories.cli:', result.stderr)
