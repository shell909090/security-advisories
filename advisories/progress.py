"""Atomic, configuration-scoped CVE progress, separate from successful checkpoints."""
import json
from pathlib import Path
from .inspection_storage import pack, unpack


class CveProgress:
    def __init__(self, state_path, config_hash):
        self.path = Path(str(state_path) + '.cve-progress.json')
        self.config_hash = config_hash

    def load(self):
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text())
        return unpack(data, 'seen') if data.get('config_hash') == self.config_hash else {}

    def save(self, records, seen):
        from advisories.storage import atomic_json
        atomic_json(self.path, pack({'config_hash': self.config_hash,
                               'records': list({row['id']: row for row in records}.values()), 'seen': seen}, 'seen'))

    def clear(self):
        self.path.unlink(missing_ok=True)


def clear_completed(state_path, config_hash, completed):
    if any(item['source'] == 'cve' for item in completed):
        CveProgress(state_path, config_hash).clear()
