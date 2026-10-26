# Recipes

Working patterns to adapt. Each one applies the rules in the other references. Credentials
come from the environment. Replace the filters with what the user needs.

## 1. Incremental vulnerability sync over raw HTTP

```python
import os
import time

import requests

BASE = os.environ.get('TIO_URL', 'https://cloud.tenable.com').rstrip('/')
TERMINAL = {'FINISHED', 'CANCELLED', 'ERROR'}


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        'X-ApiKeys': f"accessKey={os.environ['TIO_ACCESS_KEY']};secretKey={os.environ['TIO_SECRET_KEY']}",
        'Accept': 'application/json',
        'User-Agent': 'Integration/1.0 (Example Corp; Vuln Sync; Build/1.0.0)',
    })
    return s


def call(s: requests.Session, method: str, path: str, **kwargs) -> requests.Response:
    """One request with 429 / transient 5xx handling. Other errors raise."""
    for attempt in range(1, 7):
        resp = s.request(method, f'{BASE}/{path}', timeout=120, **kwargs)
        if resp.status_code in (429, 502, 503, 504) and attempt < 6:
            wait = resp.headers.get('retry-after')
            time.sleep(float(wait) if wait and wait.isdigit() else min(2 ** attempt, 60))
            continue
        if resp.status_code != 409:
            resp.raise_for_status()
        return resp
    raise RuntimeError('unreachable')


def export_vulns_since(since: int, deadline_s: int = 6 * 3600):
    """Yield every finding found or fixed since `since` (epoch seconds), all states."""
    s = session()
    body = {
        'num_assets': 1000,
        'include_unlicensed': False,
        # `since` without `state` returns OPEN, REOPENED and FIXED.
        'filters': {'since': since},
    }
    resp = call(s, 'POST', 'vulns/export', json=body)
    adopted = resp.status_code == 409
    if adopted:
        # An identical export is already running: reuse it, but don't cancel it later.
        uuid = resp.json()['active_job_id']
    else:
        uuid = resp.json()['export_uuid']
    done: set[int] = set()
    started, delay, state = time.time(), 2, 'QUEUED'
    try:
        while True:
            status = call(s, 'GET', f'vulns/export/{uuid}/status').json()
            state = status['status']
            new = [c for c in status.get('chunks_available', []) if c not in done]
            for chunk_id in new:  # chunk IDs are not sequential; download as they appear
                yield from call(s, 'GET', f'vulns/export/{uuid}/chunks/{chunk_id}').json()
                done.add(chunk_id)
            if state in TERMINAL and not new:
                if state != 'FINISHED' or status.get('chunks_failed'):
                    raise RuntimeError(f"export {uuid} ended {state}: {status.get('reason')}")
                return
            if time.time() - started > deadline_s:
                raise TimeoutError(f'export {uuid} exceeded {deadline_s}s')
            if not new:
                time.sleep(delay)
                delay = min(delay + 1, 30)
            else:
                delay = 2
    finally:
        # If we stop early (error, deadline, or the caller stops iterating), cancel the job
        # to free one of the container's 10 export slots. Never let the cleanup hide the
        # original exception.
        if state not in TERMINAL and not adopted:
            try:
                s.post(f'{BASE}/vulns/export/{uuid}/cancel', timeout=30)
            except requests.RequestException:
                pass
```

Notes:

- On a 409, this reuses the running job, which is safe because the filters are identical by
  definition.
- The cancel in `finally` runs on any early exit, including a consumer that stops iterating
  (`GeneratorExit`). It's skipped once the job is already in a terminal state, and a failed
  cancel never masks the original error.
- It's also skipped for an adopted job, which belongs to whoever started it.

## 2. The same with pyTenable, with defaults made explicit

```python
from tenable.io import TenableIO

tio = TenableIO(vendor='Example Corp', product='Vuln Sync', build='1.0.0')  # TIO_ACCESS_KEY / TIO_SECRET_KEY


def export_vulns_since(since: int):
    return tio.exports.vulns(
        since=since,
        num_assets=1000,            # pyTenable default is 500
        include_unlicensed=False,   # pyTenable default is True; the API default is False
        adopt_existing=True,        # safe here: a 409 means identical filters
    )


for finding in export_vulns_since(1760000000):
    asset_id = finding['asset']['uuid']   # join key to the asset export's `id`
```

The pyTenable iterator stops only on `FINISHED` (and raises on `ERROR`). In long-running
services, run it in a worker with an overall deadline, or use recipe 1.

## 3. Asset inventory (v2) and joining findings

```python
from tenable.io import TenableIO

tio = TenableIO()


def assets_by_id(since: int | None = None) -> dict[str, dict]:
    kwargs = {'chunk_size': 4000}          # required by the API; 100–10000
    if since:
        kwargs['since'] = since            # v2 only: updated, deleted or terminated since
    return {a['id']: a for a in tio.exports.assets_v2(**kwargs)}


def enrich(findings, assets: dict[str, dict]):
    for f in findings:
        asset = assets.get(f['asset']['uuid'])  # the embedded asset object is only a best guess
        yield {**f, 'asset_details': asset}
```

Assets v2 can't filter by tag. Use `tio.exports.assets(tags=[('Category', 'Value')],
chunk_size=4000)` (v1) when you need that.

## 4. Find a tag value's UUID and assign it (writes data: confirm with the user first)

```python
from tenable.io import TenableIO

tio = TenableIO()


def tag_value_uuid(category: str, value: str) -> str:
    # Filter by category on the server and match the value locally: `f` is
    # `field:operator:value`, so values containing ':' don't filter reliably. If the
    # category name itself contains ':', drop `f` and match both fields locally.
    matches, offset = [], 0
    while True:
        params = {'f': f'category_name:eq:{category}', 'limit': 1000, 'offset': offset}
        page = tio.get('tags/values', params=params).json()
        values = page.get('values', [])
        matches += [v for v in values if v.get('value') == value and v.get('category_name') == category]
        offset += len(values)
        if not values or offset >= page.get('pagination', {}).get('total', 0):
            break
    if len(matches) != 1:
        raise LookupError(f'{len(matches)} tag values match {category}:{value}')
    return matches[0]['uuid']


def assign_tag(asset_uuids: list[str], category: str, value: str) -> str:
    body = {'action': 'add', 'assets': asset_uuids, 'tags': [tag_value_uuid(category, value)]}
    return tio.post('tags/assets/assignments', json=body).json()['job_uuid']  # 200; applied asynchronously
```

## 5. List every scan, paginated or not

```python
from tenable.io import TenableIO

tio = TenableIO()


def all_scans(page_size: int = 200) -> list[dict]:
    first = tio.get('scans', params={'limit': page_size, 'offset': 0}).json()
    scans = list(first.get('scans') or [])
    pagination = first.get('pagination')
    if pagination:   # page only when the response says it's paginated
        while len(scans) < pagination['total']:
            page = tio.get('scans', params={'limit': page_size, 'offset': len(scans)}).json()
            if not page.get('scans'):
                break
            scans.extend(page['scans'])
    return list({s['id']: s for s in scans}.values())  # de-duplicate if the order shifted mid-paging
```

## 6. Security Center analysis paging over raw HTTP

```python
import os

import requests

SC = os.environ['TSC_URL'].rstrip('/')


def sc_vulns(filters: list[dict], page: int = 1000):
    s = requests.Session()
    s.headers['X-APIKey'] = f"accessKey={os.environ['TSC_ACCESS_KEY']}; secretKey={os.environ['TSC_SECRET_KEY']}"
    s.verify = os.environ.get('TSC_CA_BUNDLE', True)
    offset = 0
    while True:
        body = {
            'type': 'vuln',
            'sourceType': 'cumulative',
            'query': {'type': 'vuln', 'tool': 'vulndetails', 'filters': filters,
                      'startOffset': offset, 'endOffset': offset + page},
        }
        resp = s.post(f'{SC}/rest/analysis', json=body, timeout=300)
        try:
            data = resp.json()
        except ValueError:
            resp.raise_for_status()
            raise
        if data.get('error_code'):          # with HTTP 200 or an error status
            raise RuntimeError(f"{resp.status_code} {data['error_code']}: {data.get('error_msg')}")
        resp.raise_for_status()
        results = data['response'].get('results', [])
        yield from results
        offset += len(results)
        total = int(data['response'].get('totalRecords') or 0)
        if not results or offset >= total:
            return


for v in sc_vulns([{'filterName': 'severity', 'operator': '=', 'value': '3,4'}]):
    ...
```
