import datetime as dt
import json
import re
UTC=dt.timezone.utc
LEVELS={"unknown":0,"low":1,"moderate":2,"medium":2,"high":3,"critical":4}

def timestamp(value):
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(dt.timezone.utc)


def iso(value):
    return timestamp(value).isoformat(timespec='milliseconds').replace('+00:00','Z')


def base(product, ident, title, description, published, modified, url):
    return dict(id=ident,aliases=[],products=[product['id']],title=title or ident,description=description or '',severity='unknown',scores=[],published=published,modified=modified,url=url,affected=[],withdrawn=False,kind='vulnerability',references=[])


def gh_record(a,p):
    ident=a['ghsa_id']
    r=base(p,ident,a.get('summary'),a.get('description'),a.get('published_at'),a.get('updated_at'),a.get('html_url') or 'https://github.com/advisories/'+ident)
    r.update(aliases=sorted({x for x in [a.get('cve_id')]+[i.get('value') for i in a.get('identifiers',[])] if x and x!=ident}),severity=a.get('severity') or 'unknown',affected=a.get('vulnerabilities') or [],withdrawn=bool(a.get('withdrawn_at')),references=a.get('references') or [])
    metrics=a.get('cvss_severities') or {}
    if not metrics and a.get('cvss'):metrics={'cvss':a['cvss']}
    for version,m in metrics.items():
        if m and m.get('score') is not None:r['scores'].append(dict(source='GitHub',version=version,score=m['score'],vector=m.get('vector_string')))
    return r


def stamp(value):
    return value.astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def parse_time(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)


def product_matches(record, products):
    if 'containers' in record:
        containers = record['containers']
        blocks = [containers.get('cna', {})] + containers.get('adp', [])
        # A tool credited for DISCOVERING another product's bug is not the affected product.
        record = [{key: block.get(key) for key in ('title', 'descriptions', 'affected', 'references')}
                  for block in blocks]
    text = json.dumps(record, ensure_ascii=False).casefold()
    matches = []
    for product in products:
        names = product['keywords'] + product['repositories'] + [p['name'] for p in product['packages']]
        if any(re.search(r'(?<![\w])' + re.escape(name.casefold()) + r'(?![\w])', text)
               for name in names):
            matches.append(product['id'])
    return matches


def numeric_severity(number):
    return 'critical' if number >= 9 else 'high' if number >= 7 else 'medium' if number >= 4 else 'low'


def metrics_scores(metrics, source):
    result = []
    if isinstance(metrics, dict):
        metrics = [v for values in metrics.values() for v in (values if isinstance(values, list) else [values])]
    for metric in metrics or []:
        if not isinstance(metric, dict):
            continue
        for key, value in metric.items():
            if key.lower().startswith('cvss') and isinstance(value, dict) and 'baseScore' in value:
                result.append({'source': metric.get('source', source), 'version': value.get('version', key),
                               'score': value['baseScore'], 'vector': value.get('vectorString', '')})
    return result


