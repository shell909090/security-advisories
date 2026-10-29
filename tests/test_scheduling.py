"""Channel isolation, CVE priority, and failure continuation without timing guesses."""
import threading
import unittest
from advisories.scheduling import completed_jobs, grouped
from advisories.cli import build_parser


def job(source, key):
    return source, None, key, {}


class SchedulingTests(unittest.TestCase):
    def test_serial_channels_parallel_services(self):
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        active = set()
        first = set()
        jobs = [job('project', 'p1'), job('ghsa', 'g1'), job('project', 'p2'),
                job('nvd', 'n1'), job('nvd', 'n2'), job('osv', 'o1'), job('cve', 'c1')]
        def collect(item):
            name = 'github' if item[0] in ('ghsa', 'project') else item[0]
            with lock:
                self.assertNotIn(name, active)
                active.add(name)
                initial = name not in first
                first.add(name)
            if initial:
                barrier.wait(timeout=3)
            with lock:
                active.remove(name)
            if item[2] == 'p1':
                raise ValueError('expected failure')
            return item[2]
        results, errors = [], []
        for key, future in completed_jobs(jobs, collect, 4):
            try:
                results.append(future.result())
            except ValueError:
                errors.append(key)
        self.assertEqual(errors, ['p1'])
        self.assertEqual(len(results), 6)
        self.assertEqual(list(grouped(jobs))[0], 'cve')
        self.assertEqual(build_parser().parse_args(['update']).workers, 8)

    def test_single_worker_does_not_deadlock(self):
        jobs = [job('project', 'p1'), job('cve', 'c1'), job('project', 'p2')]
        calls = []
        for _, future in completed_jobs(jobs, lambda item: calls.append(item[2]), 1):
            future.result()
        self.assertEqual(calls, ['c1', 'p1', 'p2'])
