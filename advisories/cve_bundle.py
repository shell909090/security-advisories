"""Optional archive acceleration; the delta log remains the coverage authority."""
import io
import json
import logging
import re
import zipfile
from .source_common import parse_time

RELEASE = 'https://api.github.com/repos/CVEProject/cvelistV5/releases/latest'
PREFIX = 'https://github.com/CVEProject/cvelistV5/releases/download/'


def candidate_count(entries, until):
    start = until.replace(hour=0, minute=0, second=0, microsecond=0)
    return sum(start <= parse_time(e['dateUpdated']) <= until for e in entries)


def choose_asset(release, count, until):
    pattern = until.date().isoformat() + r'_delta_CVEs_at_\d{4}Z\.zip'
    for asset in release.get('assets', []):
        size = asset.get('size', 0)
        valid = (re.fullmatch(pattern, asset.get('name', ''))
                 and asset.get('browser_download_url', '').startswith(PREFIX)
                 and 0 < size <= min(16 * 1024 * 1024, count * 2048))
        if valid:
            return asset
    return None


def read_records(content, pending):
    wanted = {entry['cveId']: parse_time(entry['dateUpdated']) for entry in pending}
    records = {}
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        if sum(item.file_size for item in archive.infolist()) > 128 * 1024 * 1024:
            raise ValueError('Expanded CVE archive exceeds size limit')
        for item in archive.infolist():
            ident = item.filename.rsplit('/', 1)[-1].removesuffix('.json')
            if ident not in wanted:
                continue
            raw = json.loads(archive.read(item))
            meta = raw.get('cveMetadata', {})
            if meta.get('cveId') == ident and parse_time(meta['dateUpdated']) == wanted[ident]:
                records[ident] = raw
    return records


def load_bundle(client, pending, until):
    if not hasattr(client, 'bytes'):
        return {}
    count = candidate_count(pending, until)
    if count < 200:
        return {}
    try:
        asset = choose_asset(client.json(RELEASE), count, until)
        if not asset:
            return {}
        records = read_records(client.bytes(asset['browser_download_url']), pending)
        logging.getLogger(__name__).info('CVE archive supplies %s of %s pending records', len(records), len(pending))
        return records
    except (RuntimeError, ValueError, KeyError, TypeError, AttributeError, OSError, zipfile.BadZipFile) as exc:
        logging.getLogger(__name__).warning('CVE archive unavailable; using individual records (%s)', type(exc).__name__)
        return {}
