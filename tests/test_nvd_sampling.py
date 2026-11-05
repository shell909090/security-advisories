"""Per-run quotas use UTC date buckets and never defer mandatory checks."""
import copy
import datetime as dt
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from advisories.checkpoints import identity
from advisories.nvd_sampling import eligible_day, select_jobs
from advisories.source_common import parse_time, stamp

NOW = parse_time('2026-11-05T12:00:00Z')
PRODUCT = {'id': 'one', 'keywords': ['one'], 'packages': []}


def options(**kwargs):
    return SimpleNamespace(**{'nvd_full': False, 'since': None, 'history': False, **kwargs})


def job(index, checkpoint='2026-11-04T12:00:00Z'):
    product = dict(PRODUCT, id=str(index))
    old = {'checkpoint': checkpoint, 'collection_hash': identity('nvd', product), 'records': {}}
    return 'nvd', product, 'nvd:' + str(index), old


class NVDSamplingTests(unittest.TestCase):
    def test_freshness_boundary_and_empty_success(self):
        for seconds, mandatory in [(0, False), (259199, False), (259200, True), (-1, True)]:
            item = job(0, stamp(NOW - dt.timedelta(seconds=seconds)))
            self.assertEqual(eligible_day(options(), item[1], item[3], NOW) is None, mandatory)

    def test_missing_invalid_or_changed_checkpoint_forces_refresh(self):
        for value in (None, '', 'invalid', [], 123):
            item = job(0, value)
            self.assertIsNone(eligible_day(options(), item[1], item[3], NOW))
        item = job(0)
        self.assertIsNone(eligible_day(options(), item[1], {}, NOW))
        self.assertIsNone(eligible_day(options(), dict(item[1], keywords=['new']), item[3], NOW))

    def test_explicit_refresh_does_not_draw_random(self):
        jobs = [job(i) for i in range(6)]
        for field, value in [('nvd_full', True), ('since', '2026-01-01'), ('history', True)]:
            with patch('advisories.nvd_sampling.random.sample') as draw:
                self.assertEqual(select_jobs(jobs, options(**{field: value}), NOW), jobs)
            draw.assert_not_called()

    def test_target_rounds_up_and_preserves_other_jobs(self):
        for count in (0, 1, 2, 3, 4, 87):
            jobs = [job(i) for i in range(count)]
            other = ('cve', None, 'cve', {})
            original = copy.deepcopy(jobs)
            selected = select_jobs([other, *jobs], options(), NOW)
            self.assertEqual(len(selected) - 1, (count + 2) // 3)
            self.assertEqual(selected[0], other)
            self.assertEqual(jobs, original)
            self.assertEqual(len({item[2] for item in selected}), len(selected))

    def test_mandatory_jobs_can_exceed_quota(self):
        jobs = [job(i, '2026-11-01T00:00:00Z') for i in range(4)] + [job(4), job(5)]
        with patch('advisories.nvd_sampling.random.sample') as draw:
            self.assertEqual(select_jobs(jobs, options(), NOW), jobs[:4])
        draw.assert_not_called()

    def test_fill_oldest_group_randomly_ignores_time_of_day(self):
        jobs = [job(0, '2026-11-01T00:00:00Z'), job(1, '2026-11-03T13:00:00Z'),
                job(2, '2026-11-03T23:00:00Z'), job(3), job(4), job(5)]
        with patch('advisories.nvd_sampling.random.sample', return_value=['nvd:2']) as draw:
            self.assertEqual(select_jobs(jobs, options(), NOW), [jobs[0], jobs[2]])
        draw.assert_called_once_with(['nvd:1', 'nvd:2'], 1)

    def test_fill_spans_multiple_dates_and_normalizes_timezone(self):
        jobs = [job(0, '2026-11-03T23:30:00-02:00'), job(1, '2026-11-03T14:00:00Z')]
        jobs += [job(i, '2026-11-05T01:00:00Z') for i in range(2, 9)]
        with patch('advisories.nvd_sampling.random.sample', return_value=['nvd:8']) as draw:
            selected = select_jobs(jobs, options(), NOW)
        self.assertEqual(selected, [jobs[0], jobs[1], jobs[8]])
        draw.assert_called_once_with(['nvd:' + str(i) for i in range(2, 9)], 1)
        self.assertEqual(eligible_day(options(), jobs[0][1], jobs[0][3], NOW), dt.date(2026, 11, 4))

    def test_repeated_runs_keep_full_quota(self):
        jobs = [job(i) for i in range(6)]
        with patch('advisories.nvd_sampling.random.sample', return_value=['nvd:0', 'nvd:1']):
            first = select_jobs(jobs, options(), NOW)
        for item in first:
            item[3]['checkpoint'] = stamp(NOW)
        with patch('advisories.nvd_sampling.random.sample', return_value=['nvd:4', 'nvd:5']) as draw:
            second = select_jobs(jobs, options(), NOW)
        self.assertEqual(second, jobs[4:])
        draw.assert_called_once_with(['nvd:2', 'nvd:3', 'nvd:4', 'nvd:5'], 2)
        for item in jobs:
            item[3]['checkpoint'] = stamp(NOW)
        with patch('advisories.nvd_sampling.random.sample', return_value=['nvd:0', 'nvd:1']):
            self.assertEqual(select_jobs(jobs, options(), NOW), first)
