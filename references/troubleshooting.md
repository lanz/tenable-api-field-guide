# Troubleshooting by symptom

| Symptom | Likely cause | Fix |
|---|---|---|
| Vuln export returns far fewer findings than the UI | No time filter (30-day default window); no `state` (FIXED excluded); `include_unlicensed` false; user lacks Can View on some assets | Add `since` (or explicit `state` + `last_found`); set `include_unlicensed` deliberately; check the user's permissions |
| Vuln export has no fixed findings | `state` omitted, or `state: ["OPEN"]` | Use `since` without `state`, or include `"FIXED"` |
| `400` with `last_found` / `first_found` / `last_fixed` | `state` missing, or combined with `since` | Add `state`, and don't combine with `since` |
| Export never finishes (script hangs) | Polling loop only exits on `FINISHED`; job was `CANCELLED` (or pyTenable iterator) | Exit on `CANCELLED`/`ERROR` too; add your own deadline |
| Export is missing chunks | Looping until `total_chunks` (counts empty chunks); chunk expired (404); chunk failed (`chunks_failed`, `reason`) | Track `chunks_available`; download promptly; check `reason` on `FINISHED` |
| `409` on vuln/WAS export POST | An identical export is already running | Reuse `active_job_id` from the body, or change filters |
| `429` "Duplicate export not allowed" on asset export POST | An identical asset export is already running (asset exports return 429, not 409) | Wait for the `job_uuid` in the message to finish, or change filters; don't retry blindly |
| `429` on export POST | 10 concurrent exports already running in the container (any user) | Wait `retry-after`; cancel stale jobs (`GET …/export/status`) |
| `429` on scan details / workbench output | More than 3 concurrent calls | Serialize those calls |
| `429` on scan launch | 25 active scans | Wait, or check `io-scans-count?active=true` |
| `400` on asset export POST | `chunk_size` missing or outside 100–10000 (max 1000 with `include_resource_tags`) | Send a valid `chunk_size` |
| `415` on compliance export POST | No request body | Send `{}` at minimum |
| `400 BAD_REQUEST_UNKNOWN_PROPERTY` | A `properties` entry isn't a valid field | Use the documented property names |
| Tag filter seems ignored | Wrong format for that export, or assets v2 (no tag filters), or pyTenable ≤ 26.8.1 dropping list values | vulns/assets v1: `"tag.<Category>": [...]`; compliance: `tags: [{category, values}]`; upgrade pyTenable |
| WAS export returns nothing for a severity | Lowercase severity | WAS uses uppercase (`HIGH`) |
| `401` on every call (pyTenable) | Unauthenticated client after a misspelled kwarg or missing env var | Check the `AuthenticationWarning`; verify env var prefix (`TIO_` vs `TO_`) |
| `401` right after generating keys elsewhere | A user has one valid key pair; regenerating invalidated the old pair | Use one key pair per integration user |
| `403` | Role lacks the permission (e.g. export permission, Can View on assets) | Grant the permission; Administrators don't need Can View for exports |
| Security Center call "succeeds" but data is wrong/empty | Error inside HTTP 200 (`error_code`), or positional filters dropped because `query=`/`tool`/`type` missing | Check `error_code`; pass `tool` and `type` |
| Security Center vulns missing WAS findings | pyTenable adds `('wasVuln', '=', 'excludeWas')` to cumulative `analysis.vulns()` when you don't pass a positional `wasVuln` filter | Pass your own positional `wasVuln` filter, using a value from the SC analysis API docs; any `wasVuln` filter stops pyTenable adding the exclusion |
| `https://https://…` in an SC URL | `TenableSC(url)` positional | Pass `url=` by keyword |
| Security Center `403` with `error_code: 163` listing scans | Administrator keys: the administrator doesn't belong to an organization | Use keys for an organization user (for example a Security Manager) |
| Every Security Center scan looks scheduled | `enabled` is `"true"` even for on-demand (`template`) schedules | Check `schedule.type` |
| Security Center asset list members fail to parse as IPs | `viewableIPs` lists UUID-tracked hosts as `<host uuid>\|<address>` | Keep the part after the last `\|`; drop empty addresses |
| Nessus `{"error": "API is not available"}` on scan calls | The license doesn't include the scan API (common on Professional and Expert) | Check `license.features.scan_api`; use Nessus Manager, Security Center or VM, or parse exported `.nessus` files. Don't work around it |
| Nessus `/server/properties` returns 200 but no `license` | The API keys are wrong or were regenerated; this endpoint silently falls back to its unauthenticated view | Check the keys with `GET /session`, which returns 401 for bad keys |
| Nessus `TypeError` or wrong order when comparing `vpr_score` / `epss_score` | They're numeric strings (`"8.4"`) or `null` | Convert to numbers first; treat `null` as missing |
| Nessus scan shows no targets, or relaunch logic misfires | A never-run scan has no `info.targets`; runs also pass through `processing` | Read targets from `GET /editor/scan/{id}` (`text_targets`); treat `processing` as busy |
| Nessus TLS error even with the scanner's CA | The URL uses an IP address, but the certificate names the host | Use the host name from the certificate in the URL |
| Nessus `403 {"error": "Route not available"}` | The edition lacks that feature (for example agents or users on Professional) | Don't retry; check `license.features` |
| Nessus `TypeError: 'NoneType' object is not iterable` | An empty list came back as `null` (`"scans": null`) | Use `body.get('scans') or []` |
| Nessus export download returns 404 | The download already succeeded once (single-use), or the export failed | Stream it to a file on the first request; stop polling on `error` and 404 |
| `//` in request paths | Trailing slash on the base URL | Remove it |
| `scans.list()` returns fewer scans than the UI | A paginated `GET /scans` response read without paging, or the user can't view some scans | Page on `pagination.total`; check scan permissions |
| `GET /assets` stops at 5,000 | Endpoint cap | Use the asset export |
| Script hangs without error (non-VM pyTenable clients) | No default timeout | Pass `timeout=` |
| Repeated `ERROR` log lines for calls that eventually succeed | pyTenable logs each retried 429 at ERROR | Expected; filter or lower the `tenable` logger level |

## Generic HTTP codes (cloud APIs)

400 invalid input · 401 bad/missing key · 403 insufficient permission · 404 not found or
expired · 406 wrong `Accept` (some downloads require `application/octet-stream`) · 409
conflict (duplicate export) · 413 payload too large · 415 wrong/missing body
`Content-Type` · 429 rate or concurrency limit (`retry-after`) · 503 not ready, retry.
Source: [Common API errors](https://developer.tenable.com/docs/common-api-errors).
