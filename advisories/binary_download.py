"""Bounded archive downloads through the shared transport and source counters."""
import urllib.error
import requests


def download(client, url, source, limit):
    _, headers, _ = client.request_parts(url, None)
    proxies = {'http': client.proxy, 'https': client.proxy} if client.proxy else None
    client.metrics.add(source, requests=1)
    try:
        with client.session().get(url, headers=headers, proxies=proxies,
                                  timeout=client.timeout, stream=True) as response:
            client.metrics.add(source, requests=len(response.history),
                               response_bytes=sum(len(item.content) for item in response.history))
            if response.status_code >= 400:
                client.metrics.add(source, http_errors=1)
                read_bounded(response, client.metrics, source, limit)
                raise urllib.error.HTTPError(url, response.status_code, 'Archive download', response.headers, None)
            return read_bounded(response, client.metrics, source, limit)
    except requests.RequestException as exc:
        client.metrics.add(source, http_errors=1)
        raise urllib.error.URLError(type(exc).__name__) from None


def read_bounded(response, metrics, source, limit):
    content = bytearray()
    for chunk in response.iter_content(65536):
        metrics.add(source, response_bytes=len(chunk))
        if len(content) + len(chunk) > limit:
            raise ValueError('Archive download exceeds size limit')
        content.extend(chunk)
    return bytes(content)
