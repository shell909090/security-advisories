"""Detail time filtering uses source dates, independent of display history."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from .command_support import setup, command, record, catalog


class DetailTimeTests(unittest.TestCase):
    def test_days_since_and_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setup(root)
            now = dt.datetime.now(dt.timezone.utc)
            old = record('old', date=(now - dt.timedelta(days=5)).isoformat())
            changed = record('changed', date='2020-01-01T00:00:00Z')
            changed['modified'] = now.isoformat()
            unknown = record('unknown')
            unknown['published'] = unknown['modified'] = None
            future = record('future', date=(now + dt.timedelta(days=1)).isoformat())
            catalog(root, [old, changed, unknown, future])
            args = ('detail', '--product', 'one', '--severity', 'critical')
            text = command(root, *args)[1]
            self.assertIn('changed', text)
            for ident in ('old', 'unknown', 'future'):
                self.assertNotIn(f'— {ident}', text)
                self.assertNotIn(f'编号/别名：{ident}', text)
            self.assertIn('编号/别名：old', command(root, *args, '--days', '7')[1])
            since = (now - dt.timedelta(days=6)).isoformat()
            self.assertIn('编号/别名：old', command(root, *args, '--since', since)[1])
            full = command(root, *args, '--history')[1]
            self.assertIn('编号/别名：unknown', full)
            self.assertFalse((root / 'history.json').exists())

    def test_invalid_time_options(self):
        from advisories.cli import main
        from contextlib import redirect_stderr
        import io
        for options in [('--days', '0'), ('--days', 'nan'), ('--since', 'invalid'),
                        ('--history', '--days', '7')]:
            with self.subTest(options=options), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    main(['detail', '--product', 'one', '--severity', 'high', *options])
                self.assertEqual(result.exception.code, 2)
