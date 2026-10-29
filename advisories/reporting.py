"""Compact, severity-gated collection reports; no notification acknowledgement."""
import json

LEVEL = {'unknown': -1, 'none': 0, 'low': 1, 'moderate': 2, 'medium': 2, 'high': 3, 'critical': 4}


def compact(record, change, details=False):
    evidence = record.get('evidence', [])
    aliases = sorted(set([record['id']] + record.get('aliases', [])))
    scores = {json.dumps(s, sort_keys=True): s for e in evidence for s in e.get('scores', [])}
    result = {k: record.get(k) for k in ('id', 'products', 'severity', 'withdrawn', 'withdrawal_conflict')}
    result.update(cve_ids=[x for x in aliases if x.startswith('CVE-')],
                  ghsa_ids=[x for x in aliases if x.startswith('GHSA-')],
                  title=next((e['title'] for e in evidence if e.get('title') and not e['title'].startswith(('CVE-', 'GHSA-'))), record['id']),
                  scores=list(scores.values()), change=change, needs_review=True,
                  links=sorted({e['url'] for e in evidence if e.get('url')}),
                  sources=sorted({e['source'] for e in evidence if e.get('source')}))
    if details:
        result['evidence'] = evidence
    return result

