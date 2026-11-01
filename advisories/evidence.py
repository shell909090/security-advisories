"""Select current evidence without discarding withdrawn source records."""


def active_evidence(row):
    return [item for item in row.get('evidence', []) if not item.get('withdrawn')]


def is_kev(row):
    return not row.get('withdrawn') and any(
        item.get('source', '').split(':')[0] == 'kev' for item in active_evidence(row))


def priority(row):
    return 'critical' if is_kev(row) else row.get('severity', 'unknown')
