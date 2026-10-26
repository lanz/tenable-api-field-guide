# Rate limits, concurrency, retries and User-Agent

Sources: [API limitations](https://developer.tenable.com/docs/api-limitations),
[Rate limiting](https://developer.tenable.com/docs/rate-limiting),
[Concurrency limiting](https://developer.tenable.com/docs/concurrency-limiting),
[User-Agent header](https://developer.tenable.com/docs/user-agent-header), and pyTenable
26.10.1.

## Scope

These limits apply to the APIs on `cloud.tenable.com`: VM, WAS, Tenable One / Exposure
Management, PCI ASV and MSSP. They **don't** apply to Security Center, Cloud Security, ASM
or OT, which have no published limits.

## Rate limit

- The limit is dynamic, computed per API key per minute from platform load. **No fixed
  number is published**, so don't hardcode one.
- Exceeding it returns **429** with a `retry-after` header in seconds. Sleep for exactly that
  long, then retry the same request.
- Tenable's recommendations:
  - **Don't multi-thread API requests.**
  - Use the export APIs instead of workbenches.
  - Give each integration its own user and API key.
  - If you hit limits regularly, spread the work out over time.

## Concurrency limits

| Limit | Scope | Over the limit |
|---|---|---|
| 10 concurrent exports | Per container, shared by vulns, assets v1/v2, compliance, WAS findings, the workbench export, and Exposure Management inventory exports | 429 + `retry-after` |
| 3 concurrent requests | Per container, for `workbenches-vulnerability-output`, `workbenches-asset-vulnerability-output`, `scans-details`, `scans-host-details` and `scans-plugin-output` | 429 + `retry-after` |
| 25 active scans | Per container, including agent scan processing. Check with `io-scans-count` and `active=true` | `scans-launch` returns 429 |
| 50 concurrent reports | Per user (`vm-reports-create`) | 429 |
| A per-user limit on Exposure Management inventory export requests | Not documented. In testing, about 5 export requests within about 10 minutes triggered it | 429 "The user limit of export requests is reached, please try again later" |

Other documented limits:

- A scan chunk over 10,000 hosts, 150,000 findings or 7 GB isn't processed.
- A scan that's `pending` for more than 4 hours, or `paused` for more than 14 days, is
  aborted.
- To check many scans' status, use `scans-get-latest-status` rather than polling
  `GET /scans`.

## A minimal 429-safe client (raw HTTP)

```python
import time
import requests

def tenable_request(session: requests.Session, method: str, url: str, max_attempts: int = 6, **kwargs):
    """Send one request, honoring 429 retry-after and retrying transient 5xx responses."""
    for attempt in range(1, max_attempts + 1):
        resp = session.request(method, url, timeout=120, **kwargs)
        if resp.status_code == 429 or resp.status_code in (502, 503, 504):
            if attempt == max_attempts:
                break
            wait = resp.headers.get('retry-after')
            time.sleep(float(wait) if wait and wait.isdigit() else min(2 ** attempt, 60))
            continue
        resp.raise_for_status()
        return resp
    resp.raise_for_status()
    return resp
```

Don't retry other 4xx responses. Those are request problems, and retrying won't fix them.

## pyTenable retry behavior

- Every `APIPlatform` class retries up to **5 times**, 6 attempts in total.
- The statuses retried by default are **420, 429, 501, 502, 503 and 504**. **500 is not
  retried.**
- The wait is the `Retry-After` value when the header is present (used as is, with no upper
  bound), otherwise `attempt × 1 s` (1, 2, 3, 4, 5, 6 s). It sleeps once more after the
  final attempt before raising. A `Retry-After` given as an HTTP date, not seconds, raises
  `ValueError`.
- Connection errors and read timeouts are retried after a flat 1 s. When retries run out,
  the original `requests` exception is raised, not a `tenable.errors` class.
- Configure with constructor kwargs: `retries=` and `backoff=`.
- Per call, `retry_on=[…]` adds statuses to retry, but **only statuses pyTenable maps to an
  error class**. An unmapped status such as 520 raises a bare `APIError` immediately.
- `TenableIO` adds the headers `X-Tio-Retry-Count` and `X-Tio-Last-Request-Uuid` to retried
  requests.
- Every failed attempt is logged at ERROR level when the exception is constructed, so
  retried 429s that eventually succeed still produce ERROR log lines. The message includes
  the request URL and response body.

## Identify your integration (User-Agent)

Tenable recommends, and its technology-partner validation requires, a User-Agent of the form:

```
Integration/1.0 (<Vendor>; <Product>; Build/<version>)
```

pyTenable builds it from constructor kwargs:

```python
tio = TenableIO(vendor='Acme', product='Acme Sync', build='2.1.0')
# User-Agent: Integration/1.0 (Acme; Acme Sync; Build/2.1.0) pyTenable/26.10.1 (Restfly/…; Python/…; …)
```
