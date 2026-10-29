from source_common import *
import datetime as dt
import re
NAME='nvd'
GLOBAL=False

def query_keywords(product):
    explicit=product.get('nvd_keywords')
    names=explicit if explicit is not None else product['keywords']
    keywords=list({name.strip().casefold():name.strip() for name in names if name.strip()}.values())
    if explicit is not None or not keywords:
        return keywords
    tokens=[set(re.findall(r'[a-z0-9]+', name.casefold())) for name in keywords]
    common=set.intersection(*tokens)
    useful=[token for token in common if len(token)>=5]
    # Broad common-token discovery replaces redundant alias requests. Product
    # relevance must still be verified downstream; this is not an exact match.
    return [sorted(useful,key=lambda token:(-len(token),token))[0]] if useful else keywords

def nvd_record(a,p):
    ident=a['id']; desc=next((d['value'] for d in a.get('descriptions',[]) if d.get('lang')=='en'),'')
    r=base(p,ident,desc.split('\n')[0][:180] or ident,desc,a.get('published'),a.get('lastModified'),'https://nvd.nist.gov/vuln/detail/'+ident)
    r.update(affected=a.get('configurations') or [],withdrawn=a.get('vulnStatus')=='Rejected',references=[x['url'] for x in a.get('references',[]) if x.get('url')])
    levels = [add_metric(r, metric) for group in (a.get('metrics') or {}).values()
              for metric in group if (metric.get('cvssData') or {}).get('baseScore') is not None]
    if levels:
        r['severity'] = max(levels, key=lambda x: LEVELS.get(x, 0))
    return r


def nvd_product(client, product, since=None, until=None):
    windows = date_windows(since, until)
    for keyword in query_keywords(product):
        for window in windows:
            yield from nvd_page_records(client, product, keyword, window)


def collect(client, product, since, until, context):
    return {"records": list(nvd_product(client, product, since, until)), "metadata": {}}

MATCH_BASIS = 'keyword-candidate'


def add_metric(record, metric):
    data = metric['cvssData']
    record['scores'].append(dict(source=metric.get('source') or 'NVD',
                                version=data.get('version'), score=data['baseScore'],
                                vector=data.get('vectorString')))
    level = (data.get('baseSeverity') or metric.get('baseSeverity') or '').lower()
    if level:
        return level
    score = data['baseScore']
    return 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'


def date_windows(since, until):
    windows=[{}]
    if since:
        start=timestamp(since);end=timestamp(until or dt.datetime.now(dt.timezone.utc))
        if start>end:raise ValueError('since is later than until')
        windows=[]
        while start<end:
            stop=min(start+dt.timedelta(days=120),end)
            windows.append({'lastModStartDate':iso(start),'lastModEndDate':iso(stop)})
            start=stop
    return windows


def nvd_page_records(client, product, keyword, window):
    index=0
    while True:
        params=dict(window,keywordSearch=keyword,resultsPerPage=2000,startIndex=index)
        response=client.json('https://services.nvd.nist.gov/rest/json/cves/2.0',params=params)
        rows=response['vulnerabilities']
        for row in rows:yield nvd_record(row['cve'],product)
        index+=len(rows)
        if index>=response['totalResults']:break
        if not rows:raise ValueError('NVD empty page before totalResults')
