"""One active job per service channel; only ready work occupies executor threads."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED


def channel(source):
    return 'github' if source in ('ghsa', 'project') else source


def grouped(jobs):
    queues = {}
    for job in jobs:
        queues.setdefault(channel(job[0]), deque()).append(job)
    return dict(sorted(queues.items(), key=lambda item: item[0] != 'cve'))


def completed_jobs(jobs, collect, workers):
    queues = grouped(jobs)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        active = {}
        for name, queue in queues.items():
            job = queue.popleft()
            active[executor.submit(collect, job)] = (name, job)
        while active:
            done, _ = wait(active, return_when=FIRST_COMPLETED)
            for future in done:
                name, job = active.pop(future)
                yield job[2], future
                if queues[name]:
                    job = queues[name].popleft()
                    active[executor.submit(collect, job)] = (name, job)
