"""One active job per service channel; only ready work occupies executor threads."""
from collections import deque
import logging
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED


def channel(source):
    return 'github' if source in ('ghsa', 'project') else source


def grouped(jobs):
    queues = {}
    for job in jobs:
        queues.setdefault(channel(job[0]), deque()).append(job)
    return dict(sorted(queues.items(), key=lambda item: item[0] != 'cve'))


def completed_jobs(jobs, collect, workers, cancel=None):
    queues = grouped(jobs)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        active = {}
        for name, queue in queues.items():
            job = queue.popleft()
            active[executor.submit(collect, job)] = (name, job)
        while active:
            done = wait_ready(active, cancel)
            for future in done:
                name, job = active.pop(future)
                yield job[2], future
                if queues[name]:
                    job = queues[name].popleft()
                    active[executor.submit(collect, job)] = (name, job)


def wait_ready(active, cancel):
    try:
        done, _ = wait(active, timeout=30, return_when=FIRST_COMPLETED)
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning('Cancelling update; waiting for in-flight requests')
        if cancel:
            cancel()
        for future in active:
            future.cancel()
        raise
    if not done:
        logging.getLogger(__name__).info('Still running: %s',
            ', '.join(job[2] for _, job in active.values()))
    return done
