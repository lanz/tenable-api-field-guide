# Security Center (Tenable.sc)

Security Center has no OpenAPI spec on developer.tenable.com. Its API reference is at
docs.tenable.com, under Security Center › API. The rules below come from that API's
behavior as implemented and tested in pyTenable 26.10.1, live API behavior, and the
Security Center user guide.

## Basics

- The base path is `https://<sc-host>/rest/`. Auth: `X-APIKey: accessKey=…; secretKey=…`,
  which needs SC 5.13+, or a certificate. Username/password sessions (`POST /rest/token`)
  are deprecated.
- **Every response is an envelope**:
  `{"type": …, "response": …, "error_code": 0, "error_msg": "", "warnings": [], "timestamp": …}`.
  **Errors can arrive with HTTP 200 and a non-zero `error_code`.** Check `error_code` on
  every response, not just the status. pyTenable raises `APIError` for you, and expects
  `error_code` to be present: a JSON body without it raises `KeyError`, so include
  `"error_code": 0` in test mocks.
- Many booleans and IDs are **strings** on the wire (`"true"`, `"12"`). Compare as strings or
  convert explicitly.
- `fields` is a comma-separated string: `?fields=id,name,status`.
- With keys, pyTenable's first request is an unauthenticated `GET /rest/system` for the
  version check. Mock it in tests.
- pyTenable defaults to `ssl_verify=False` and a 300 s timeout. Many installations use
  self-signed or private-CA certificates, so the default never fails and never checks
  anything. Pass `ssl_verify=True`, or the path to the CA bundle.
- List endpoints (`GET /rest/scan`, `/rest/asset`, `/rest/policy` …) return
  `{"usable": [...], "manageable": [...]}`. The two lists overlap, so merge them and
  de-duplicate by `id`.

## Accounts and roles

- **Use an organization user, not an administrator.** The administrator account configures
  the platform but doesn't belong to an organization, so it can't see the organization's
  data. Listing scans with an administrator's keys returns **HTTP 403** with
  `error_code: 163` ("Administrators may not manage Scans."). pyTenable raises a plain
  `APIError` with `.code == 403`.
- Security Manager, SM-Linked, Security Analyst and Vulnerability Analyst can work with
  scans. Auditor can't. Results only cover the scans, asset lists and repositories the user
  can use or manage.

## Scans and schedules

- `GET /rest/scan?fields=…` returns every scan's targets (`ipList`, `assets`), repository,
  zone, policy, credentials and schedule in one call. There's no per-scan editor request
  as in VM.
- `schedule.type` is one of `ical`, `dependent`, `rollover`, `template`, `now` or `never`.
  - `ical` scans run on `repeatRule` (an RRULE), starting at `start`.
  - `dependent` scans run after the scan in `schedule.dependent`.
  - **`template` means on demand.** It still reports `enabled: "true"`, so decide whether a
    scan is scheduled from `type`, not from `enabled`.
- `type: "plugin"` scans run a single plugin (`plugin.id`) instead of a policy.

## Asset lists

- **Literal lists** keep their members in `typeFields`:
  - `static` and `watchlist` use `definedIPs`, a comma-separated string. A watchlist holds
    IPs that aren't in a repository.
  - `dnsname` uses `definedDNSNames`.
  - `GET /rest/asset?fields=id,name,type,typeFields` doesn't always include `typeFields`.
    Read a list missing them with `GET /rest/asset/{id}`.
- **Rule-based lists** (`dynamic`, `combination`, `ldapquery` …) are defined by rules, so
  their members aren't in the definition. Read the current members from
  `GET /rest/asset/{id}?fields=id,name,type,viewableIPs`, one list at a time. Requesting
  `viewableIPs` for every list at once can be slow.
  - `viewableIPs` is a list of `{repository, ipList, ipCount}` entries, one per
    repository. `ipList` is newline-separated.
  - **Hosts tracked by UUID appear as `<host uuid>|<address>`**, and the address can be
    empty. Keep the part after the last `|`, and drop empty entries.
  - Members only cover repositories the user can see, and they change as hosts are
    rescanned.
- Asset lists also drive analysis, dashboards, reports and user access. A list that no scan
  uses isn't unused.

## Freeze windows

- `GET /rest/freeze` lists freeze windows, which are time frames when scans skip certain
  targets. Older versions call them blackout windows, at `GET /rest/blackout`. Try
  `freeze`, and fall back to `blackout` on an error.
- A window covers IPs (`ipList`), asset lists (`assets`), or everything (`allIPs: "true"`,
  "All Systems" in the UI). If it sets a repository, it applies only to scans that import
  into that repository.
- While a window is active, scans skip the covered targets. **A scan with no targets left
  outside the window aborts.**
  - Agent and web app scans that are already running aren't stopped.
  - Linked scans are checked only when they start.

## Analysis queries (vulnerabilities, events)

Raw request shape for `POST /rest/analysis`:

```json
{
  "type": "vuln",
  "sourceType": "cumulative",
  "query": {
    "type": "vuln",
    "tool": "vulndetails",
    "startOffset": 0,
    "endOffset": 1000,
    "filters": [
      {"filterName": "severity", "operator": "=", "value": "3,4"}
    ]
  }
}
```

- Page by advancing `startOffset`/`endOffset`. Stop when you've read `totalRecords` or a page
  comes back short.
- `sourceType: "individual"` with a `scanID` queries one scan result instead of the
  cumulative database.

## pyTenable

```python
from tenable.sc import TenableSC

sc = TenableSC(url='https://sc.example.com', access_key=AK, secret_key=SK)  # keywords only
for vuln in sc.analysis.vulns(('severity', '=', '3,4'), ('exploitAvailable', '=', 'true')):
    ...
```

- **Filters are 3-tuples** `(filterName, operator, value)`. A 2-tuple raises `IndexError`.
  - A later filter with the same name replaces an earlier one.
  - A filter whose operator *or* value is `None` is removed.
  - A `list[int]` value expands to `[{'id': '1'}, …]`.
- Asset combinations use nested lowercase tuples: `('asset', '~', ('and', 12, ('not', 14)))`.
- **Positional filters are ignored** when you also pass `query=`, or when `tool` and `type`
  aren't both set.
- `sc.analysis.vulns()`:
  - It defaults to `tool='vulndetails'` and `sourceType='cumulative'`.
  - **For cumulative queries it adds `('wasVuln', '=', 'excludeWas')`**, which excludes Web
    App Scanning findings, unless you pass a `wasVuln` filter. Filters passed as `filters=[…]`
    instead of positionally skip that addition.
  - `scan_id=` switches to individual mode.
  - `tool='iplist'` returns a single raw response dict, not an iterator.
- The analysis iterator pages 1,000 at a time and **mutates the query dict you pass in**.
  Deep-copy it if you reuse it. `json_result=True` returns one page.
- If `totalRecords` is missing or wrong, pyTenable logs an "API Recordkeeping error" warning
  and keeps reading while pages are full.
- `sc.hosts.search(...)` uses a different filter shape: `property` / `operator` / `value`
  under `and`/`or`.
- `with TenableSC(...) as sc:` logs out on exit **only for session auth**. Key and
  certificate sessions don't log out.
