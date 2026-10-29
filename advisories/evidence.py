"""Select current evidence without discarding withdrawn source records."""


def active_evidence(row):
    return [item for item in row.get('evidence', []) if not item.get('withdrawn')]
