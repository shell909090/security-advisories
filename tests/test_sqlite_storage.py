"""JSONB round trips, partial reads, atomic replacement and incremental writes."""
import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from advisories.sqlite_storage import save_sqlite, load_sqlite, write_nodes, vacuum
from advisories.storage import save_state, load_state


class SQLiteStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.sqlite'
        self.state = {'version': 1, 'units': {'cve': {'checkpoint': 'old', 'records': {},
            'cve_seen': {'CVE-1': {'checked_at': 'now', 'products': {'one': 'hash'}}}}},
            'catalog': {'one': {'records': [{'id': 'a', 'nested': [None, True, '中文', 1.5]}]},
                        'two': {'records': []}}, 'source_caches': {'osv': {'details': {}, 'indexes': {}}}}

    def test_roundtrip_and_jsonb(self):
        save_state(self.path, self.state)
        self.assertEqual(load_state(self.path), self.state)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT DISTINCT typeof(body) FROM nodes').fetchall(), [('blob',)])
        changed = copy.deepcopy(self.state)
        changed['catalog']['one']['records'] = []
        del changed['catalog']['two']
        save_state(self.path, changed)
        self.assertEqual(load_state(self.path), changed)
        with sqlite3.connect(self.path) as connection:
            paths = [row[0] for row in connection.execute('SELECT path FROM nodes')]
        self.assertNotIn('["catalog","one","records",0]', paths)
        self.assertNotIn('["catalog","two"]', paths)

    def test_failure_rolls_back_checkpoint_and_records(self):
        save_state(self.path, self.state)
        changed = copy.deepcopy(self.state)
        changed['units']['cve']['checkpoint'] = 'new'
        changed['catalog']['one']['records'] = []
        def fail(connection, state):
            write_nodes(connection, state)
            raise OSError('disk full')
        with patch('advisories.sqlite_storage.write_nodes', side_effect=fail):
            with self.assertRaises(OSError):
                save_state(self.path, changed)
        self.assertEqual(load_state(self.path), self.state)

    def test_catalog_does_not_load_other_products_or_units(self):
        save_state(self.path, self.state)
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE nodes SET body=x'ff' WHERE path IN (?, ?)",
                               ('["units"]', '["catalog","two"]'))
        loaded = load_state(self.path, products=['one', 'missing'])
        self.assertEqual(loaded['catalog'], {'one': self.state['catalog']['one']})
        with self.assertRaises(sqlite3.DatabaseError):
            load_state(self.path)

    def test_unchanged_nodes_are_not_rewritten(self):
        save_sqlite(self.path, self.state)
        with sqlite3.connect(self.path) as connection:
            connection.execute('CREATE TABLE changes (path TEXT)')
            connection.execute('CREATE TRIGGER track AFTER UPDATE ON nodes BEGIN '
                               'INSERT INTO changes VALUES (new.path); END')
        save_sqlite(self.path, self.state)
        self.state['units']['cve']['checkpoint'] = 'new'
        save_sqlite(self.path, self.state)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT path FROM changes').fetchall(),
                             [('["units","cve","checkpoint"]',)])

    def test_foreign_database_is_rejected(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute('CREATE TABLE valuable (value TEXT)')
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            save_sqlite(self.path, self.state)
        self.assertEqual(before, self.path.read_bytes())
        with self.assertRaises(ValueError):
            load_sqlite(self.path)

    def test_save_reclaims_deleted_pages(self):
        self.state['catalog']['one']['records'] = [{'id': str(i), 'text': 'x' * 16000} for i in range(64)]
        save_state(self.path, self.state)
        large = self.path.stat().st_size
        self.state['catalog']['one']['records'] = []
        save_state(self.path, self.state)
        self.assertLess(self.path.stat().st_size, large // 4)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('PRAGMA freelist_count').fetchone()[0], 0)
        self.assertEqual(load_state(self.path), self.state)

    def test_vacuum_failure_preserves_committed_state(self):
        from unittest.mock import Mock
        failed_connection = Mock()
        failed_connection.execute.side_effect = sqlite3.OperationalError('disk full')
        def fail_vacuum(connection):
            self.assertFalse(connection.in_transaction)
            vacuum(failed_connection)
        with patch('advisories.sqlite_storage.vacuum', side_effect=fail_vacuum):
            with self.assertLogs('advisories.sqlite_storage', level='WARNING') as logs:
                save_state(self.path, self.state)
        self.assertIn('State saved', logs.output[0])
        self.assertEqual(load_state(self.path), self.state)

    def test_failed_transaction_does_not_vacuum(self):
        save_state(self.path, self.state)
        with patch('advisories.sqlite_storage.write_nodes', side_effect=OSError('disk full')):
            with patch('advisories.sqlite_storage.vacuum') as maintenance:
                with self.assertRaises(OSError):
                    save_state(self.path, self.state)
        maintenance.assert_not_called()
