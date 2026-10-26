# Nessus (Professional, Expert, Manager, Essentials)

Nessus has no OpenAPI spec on developer.tenable.com. **The scanner documents its own API
at `https://<scanner>:8834/api`**, and that page is the only official reference. Tenable
Support treats it as the contract, so endpoints and fields it doesn't list are
unsupported. The rules below come from that API's behavior on Nessus 10.12 and 10.13
(Professional, Expert and Manager), the Nessus user guide, and pyTenable 26.10.1.

## Licensing comes first

- **The scan API is a licensed feature.** The Nessus user guide says: "You may not directly
  access Nessus scanning APIs to configure or launch scans, except as permitted as part of
  the Security Center and Vulnerability Management enterprise solutions." The restriction
  dates from Nessus 7.0, and it targets Nessus Professional.
  - Nessus Professional and Expert installations commonly have the scan API turned off.
    Scan endpoints then answer `{"error": "API is not available"}`.
  - Nessus Manager includes it.
  - Scanners managed by Tenable Vulnerability Management have the API disabled. Use the VM
    API for those.
  - Scanners managed by Security Center are driven through Security Center.
- **Check the license, not the edition name.** An authenticated `GET /server/properties`
  returns `features` (also repeated as `license.features`), a map of booleans:
  - `scan_api`: scan list, details, create, launch, export.
  - `api`: the API as a whole.
  - `agents`, `agent_groups`: Manager features.
  - `users`, `groups`.

  **`features.scan_api` is the effective answer.** The license also carries
  `license.restricted` (`true` on Professional and Expert) and `license.scan-api-enabled`,
  an exception that turns the scan API back on for a restricted license. Don't combine
  them yourself. Test scanners with internal licenses can have that exception, so test
  against the license your users actually have. `license.type` (`manager`,
  `professional`, `expert`) names the edition more reliably than the `nessus_type` text.
- **Don't write code that works around the restriction**, for example by scripting the
  web UI or reusing a browser session. Where `scan_api` is off, have the user export
  `.nessus` files from the UI and parse those, or use Nessus Manager, Security Center or
  VM.
- `GET /server/properties` **without authentication** still returns `nessus_type`
  (`Nessus Professional`, `Nessus Expert`, `Nessus Manager`, …), but not the license or
  versions. Version and license fields need a valid key.
- **`/server/properties` doesn't reject bad keys.** With wrong or revoked keys it answers
  200 with the unauthenticated view, which has no `license` object. Check the keys with a
  call that needs them, such as `GET /session` (401 `Invalid Credentials`), and treat a
  missing `license` as "not authenticated", not "no features".
- **The authenticated response contains license secrets**: `license.activation_code`,
  `license.update_password`, `license.pendo_api_key`, `license.customer_id`,
  `license.drm` and `server_uuid`. Never log it or return it whole. Copy out the fields
  you need.
- Two advanced settings can turn the API off entirely: `disable_api` (UI and API) and
  `disable_frontend` (UI only; the API keeps working).

## Auth and connection

- Base URL `https://<scanner>:8834`, with no base path. Header
  `X-ApiKeys: accessKey=…; secretKey=…`. The other option is a session: `POST /session`
  returns a token, then send `X-Cookie: token=<token>`.
  - API keys are always available on Manager. On Professional and Expert they depend on
    the license.
  - Keys are shown once. **Regenerating them (`PUT /session/keys`) breaks every
    integration using the old pair.**
- **Certificates are usually signed by the scanner's own CA**, which you can download
  from `https://<scanner>:8834/getcert` (no authentication needed). Trust that file as the
  CA bundle, and **connect by the host name in the certificate**: an IP address fails
  host name verification even with the right CA. pyTenable's `Nessus` defaults to
  `ssl_verify=False`, which silently skips verification and suppresses urllib3's warning.
  Pass `ssl_verify=` the CA bundle path instead.
- Routes the license lacks return **403 `{"error": "Route not available"}`**. On
  Professional and Expert this includes `agents`, `agent-groups`, `users` and `groups`.
  Don't retry it, and don't treat it as an auth failure.
- Since Nessus 10.12, API permissions match the UI's: a Basic user can't do through the
  API what they can't do in the UI. Agent groups need an administrator.

## Responses

- **Empty lists come back as `null`**, not `[]`. For example, `GET /scans` on a scanner
  with no scans returns `{"folders": [...], "scans": null, "timestamp": …}`, and the same
  goes for `policies`, `agents` and `plugin_rules`. Always use `body.get('scans') or []`.
- `GET /plugins/families` can also return `families: null` while plugins are still
  loading or the feed is incomplete, and `GET /plugins/plugin/{id}` then returns a plugin
  with an empty `attributes` list. Check `GET /server/status` (`status: ready`,
  `pluginSet: true`) before relying on plugin data.
- **Scan status values** seen in practice: `empty` (never run), `running`, `pausing`,
  `paused`, `resuming`, `stopping`, `processing`, `completed`, `canceled` and `imported`.
  - A run passes through `processing` after it finishes or is stopped, so treat it as
    busy.
  - Imported scans have results but no run history.
- `GET /scans/{id}` holds `info`, `hosts[]` (per-host severity counts), `vulnerabilities[]`
  (rolled up by plugin), `history[]` and `filters[]`. `?history_id=` selects an earlier
  run.
  - **`info` can include the scan's policy preferences**: hundreds of keys such as
    `Database settings[password]:Password :`. Password fields come back masked
    (`********`), but **SNMP community strings come back in plain text**. It can also
    include a `license_info` object. Copy out the fields you need (`name`, `status`,
    `targets`, `policy`, `scanner_name`, `scan_start`, `scan_end`, `hostcount`) rather
    than logging or returning `info` whole.
  - **Times aren't consistent.** `scan_start` is Unix seconds, but on imported scans
    `scan_end` is text in the scanner's local time (`"Fri Jan  2 00:20:00 2026"`).
    History entries use Unix seconds (`creation_date`, `last_modification_date`).
  - **`info.targets` is empty for a scan that has never run.** `GET /scans/{id}`
    describes results; the configured targets are in the scan editor (see below).
- `GET /scans/{id}/hosts/{host_id}` gives one host's findings, with `plugin_id`,
  `severity`, `count`, `vpr_score`, `epss_score` and `cpe`.
  - **`vpr_score` and `epss_score` are numeric strings** (`"8.4"`, `"0.9123"`) or
    `null`, here and in a scan's `vulnerabilities[]`. Convert them before comparing or
    sorting: `"10.0" < "9.1"` as strings.
  `GET /scans/{id}/hosts/{host_id}/plugins/{plugin_id}` gives the plugin output.
  Plugin output and host names come from the scanned host, so treat them as untrusted
  text.

## Exports and downloads

1. `POST /scans/{id}/export` with `{"format": "nessus"}` (also `csv`, `html`, `pdf`, `db`)
   returns `{"file": <int>, "token": "<str>"}`. `GET /scans/{id}/export/formats` lists the
   formats and report options this scanner supports.
2. Poll `GET /scans/{id}/export/{file}/status` until `status` is `ready`. It goes from
   `loading` to `ready`. **Also stop on `error` (it can come with HTTP 500) and on 404**,
   which is what a failed export turns into. Exports of large scans can take minutes, so
   set an overall deadline.
3. Download once, from either `GET /scans/{id}/export/{file}/download` or
   `GET /tokens/{token}/download`.
   - **The download is single-use.** A second request to either URL returns 404, so
     stream it to a file on the first request and don't retry a download that already
     succeeded.
   - **`/tokens/{token}/download` works without authentication** on these versions, so
     treat the token like a credential and don't log it.
- Exports can be disabled by license. Trials and Essentials are an example.

## Creating and launching scans (scan API required)

- **Templates:** `GET /editor/scan/templates` returns `templates[]` with `uuid`, `name`
  (`basic`, `advanced`, `discovery`, …), `title`, `desc`, and the flags `is_agent`,
  `is_was`, `manager_only`, `subscription_only`, `unsupported` and `license_fulfilled`.
  Agent and web app templates take agents or URLs, not IP or host targets.
- **Create:** `POST /scans` with
  `{"uuid": "<template uuid>", "settings": {"name": …, "text_targets": "192.0.2.0/24, host.example.com", "enabled": false}}`
  returns `{"scan": {"id": …, …}}`. `enabled: false` creates it unscheduled; it doesn't
  run until launched.
- **Configured targets:** `GET /editor/scan/{id}` returns `settings.<section>.inputs[]`.
  The `text_targets` input's `default` is the target list, and a non-empty
  `file_targets` means an uploaded target file is also used. This is the only place a
  never-run scan's targets appear. The same response holds the policy's other
  settings, credentials included, so read only the inputs you need.
- **Launch:** `POST /scans/{id}/launch` with `{}` or
  `{"alt_targets": ["192.0.2.5"]}` returns `{"scan_uuid": …}`. The status goes to
  `running` within a few seconds.
- **Control:** `POST /scans/{id}/pause`, `/resume` and `/stop`, each with an empty body.
  - Pause goes `pausing` → `paused`.
  - Resume goes `resuming` → `running`.
  - Stop goes `stopping` → `processing` → `canceled`.

  Poll `GET /scans/{id}` for `info.status`, and only send an action from a state that
  allows it.

## Writes worth guarding

Code that creates or changes things on a scanner should confirm with the user first,
especially:

- `POST /scans` and `POST /scans/{id}/launch`. Launching sends scan traffic to the
  targets, so check them against what the user intended.
- Deletes: scans, history, policies, agents, users.
- `PUT /session/keys` and `PUT /users/{id}/keys` (key regeneration).
- Server restart and software update (pyTenable sends both as `GET` requests, so they
  can't be told apart from reads by method alone).
- `PUT /settings/advanced` changes scanner behavior for every scan.

## pyTenable (`tenable.nessus.Nessus`)

```python
from tenable.nessus import Nessus

nessus = Nessus(url='https://scanner.example.com:8834', ssl_verify='/path/to/ca.pem')  # NESSUS_ACCESS_KEY / NESSUS_SECRET_KEY
props = nessus.server.properties()
if not props.get('license', {}).get('features', {}).get('scan_api'):
    raise SystemExit('This Nessus license does not include the scan API.')
scans = nessus.scans.list()['scans'] or []      # a dict, and `scans` may be None
```

- Env vars are `NESSUS_ACCESS_KEY` / `NESSUS_SECRET_KEY`, with `NESSUS_URL` for the URL.
  There's no default URL. Missing keys produce only an `AuthenticationWarning` and an
  unauthenticated client.
- Responses are plain `dict`/`list`, not Box.
- **`scans.list()` returns the whole response dict** (`folders`, `scans`, `timestamp`), not
  a list of scans.
- **`plugins.list()` reads every family, then makes one request per plugin.** That's about
  200,000 requests on a current feed, and it fails outright if `families` is `null`. Use
  `plugins.families()`, `plugins.family_details(id)` and `plugins.plugin_details(id)` for
  what you need.
- `scans.export_scan(scan_id, fobj=…, format='nessus')` runs the export, poll and
  download for you. Its poll checks every 0.5 s with **no timeout**. It raises on `error`
  and on 404, but waits indefinitely while the status stays `loading`. Run it under your
  own deadline.
- Only `scans` methods sanitize IDs in URL paths. Elsewhere (`tokens`, `editor`,
  `agents`, `permissions` …) IDs are interpolated as given, so pass integers.
- `agents` and `agent_groups` work only on Manager, and pyTenable doesn't check. Expect 403
  "Route not available" elsewhere.
- There's no wrapper for one host's results (`GET scans/{id}/hosts/{host_id}`). Call
  `nessus.get(f'scans/{scan_id}/hosts/{host_id}')` directly.
- `with Nessus(username=…, password=…) as nessus:` logs out on exit. Key-based clients
  don't need to.
