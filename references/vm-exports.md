# Vulnerability Management exports

The export APIs are the supported way to pull bulk data out of VM. The workbench endpoints
are capped at 5,000 records and partly deprecated. Sources:
[Retrieve vulnerability data](https://developer.tenable.com/docs/retrieve-vulnerability-data),
[Refine vulnerability export requests](https://developer.tenable.com/docs/refine-vulnerability-export-requests),
[Retrieve asset data](https://developer.tenable.com/docs/retrieve-asset-data),
[VM and WAS integrations](https://developer.tenable.com/docs/vm-and-was-integrations), the
export specs (operationIds below), and pyTenable 26.10.1.

## Lifecycle (all export types)

1. `POST` the request. The response is `{"export_uuid": "…"}`.
2. Poll `GET …/{export_uuid}/status`. Each response lists `chunks_available`.
3. `GET …/{export_uuid}/chunks/{chunk_id}` for each new chunk, as soon as it appears.
4. Stop when the status is `FINISHED`, **or** `CANCELLED`, **or** `ERROR`, and every
   available chunk has been downloaded.

| Export | Create (operationId) | Status, chunks, cancel under |
|---|---|---|
| Vulnerabilities | `POST /vulns/export` (`exports-vulns-request-export`) | `/vulns/export/{uuid}/…` |
| Assets v1 | `POST /assets/export` (`export-assets-v1`) | `/assets/export/{uuid}/…` |
| Assets v2 | `POST /assets/v2/export` (`export-assets-v2`) | **`/assets/export/{uuid}/…`** (the v1 paths) |
| Compliance | `POST /compliance/export` (`io-exports-compliance-create`) | `/compliance/export/{uuid}/…` |
| WAS findings | `POST /was/v1/export/vulns` (`was-export-findings`) | `/was/v1/export/vulns/{uuid}/…` |

`GET …/export/status`, with no UUID, lists recent jobs. For vulns that means the last 1,000
jobs; completed jobs only appear for three days.

### Status values

- Vulns, assets and WAS: `QUEUED`, `PROCESSING`, `FINISHED`, `CANCELLED` (two Ls), `ERROR`.
- Compliance uses `PROCESSING`, **`READY`**, `FINISHED`, `CANCELLED` and `ERROR`. It has no
  `QUEUED`, and `READY` means some chunks are downloadable while processing continues.
- A `FINISHED` vuln export can still carry a `reason` such as "N of M chunks failed to
  process". Check `chunks_failed` and `reason`, not only `status`.
- If one chunk fails, every chunk queued after it is cancelled.

### Chunks

- Chunks finish in parallel and out of order. Chunk IDs aren't sequential and may not start
  at 1.
- Empty chunks are counted in `total_chunks` but never appear in `chunks_available`, so
  never loop until `len(downloaded) == total_chunks`.
- A chunk that isn't ready returns 400. One that's expired or unknown returns 404.
- **Expiry:** the published sources disagree. The vulnerability data guide says chunks stay
  downloadable for 3 days after completion, and the chunk download reference says 24 hours
  after creation. **Plan for 24 hours**, which is safe either way. Compliance chunks are
  kept 3 days (since 2025-11-19).
- Each finding's plugin output is capped at 1,024 KB. Findings from PCI scans can't be
  exported.

### Duplicates and limits

- A **vulnerability or WAS** export identical to one still running returns **409** with
  `{"active_job_id": "<uuid>", "failure_reason": "…"}`. It used to return 429, so older
  integrations may still treat a duplicate as a rate limit.
  Either use the active job, or change the filters if you really need a separate job.
- **Asset exports are different.** In testing, an identical asset export (v1 or v2)
  returned **429**, with `retry-after` and
  `{"status": 429, "message": "Duplicate export not allowed. … (job_uuid=<uuid> …)"}`. The
  running job's UUID appears only inside `message`, and the original job keeps running.
  - Distinguish this from a concurrency 429 by the message.
  - Don't retry it blindly: it repeats until the first job finishes. Wait for that job
    (parse `job_uuid` from the message) or change the filters.
- No more than **10 concurrent exports per container**, shared by every export type and
  every user. The 11th returns 429 with `retry-after`.
- Compliance exports running longer than 24 hours are cancelled automatically.
- Permissions: Basic role or the `VM_EXPLORE` export permission, plus Can View on the
  assets. An Administrator doesn't need explicit Can View.

## Vulnerability export request

```json
{
  "num_assets": 500,
  "include_unlicensed": false,
  "filters": {
    "since": 1760000000,
    "severity": ["medium", "high", "critical"],
    "tag.Location": ["Dallas", "Austin"]
  }
}
```

### Defaults that change results

| Behavior | Rule |
|---|---|
| No time filter | **Only findings found or fixed in the last 30 days.** Time filters are `since`, `indexed_at`, `first_found`, `last_found` and `last_fixed` |
| No `state` filter | **Only `OPEN` and `REOPENED`. FIXED is excluded** |
| `since` with no `state` | **OPEN, REOPENED and FIXED.** OPEN/REOPENED match on `last_found >= since`, FIXED on `last_fixed >= since`. This is the recommended incremental-sync filter |
| `since` combined with `first_found`, `first_seen`, `last_found`, `last_seen` or `last_fixed` | Not allowed |
| `first_found`, `last_found` or `last_fixed` | `state` is **required** |
| `include_unlicensed` | API default `false`, so assets past their licensed period are excluded |
| `num_assets` | Assets per chunk, not findings. Default 50, range 50–5000. **Out-of-range values are clamped**, not rejected. Tenable recommends 1,000–3,000 for integrations |

### Filters

- Time filters are 10-digit Unix timestamps in **seconds**: `since`, `first_found` (alias
  `first_seen`), `last_found` (alias `last_seen`), `last_fixed`, `indexed_at` and
  `resurfaced_date`.
- `state`: `OPEN`, `REOPENED`, `FIXED`. Case-insensitive. The UI's "new" and "active" map to
  OPEN, and "resurfaced" to REOPENED.
- `severity`: **lowercase** `info`, `low`, `medium`, `high`, `critical`.
- `tag.<Category>`: replace `<Category>` with the category name, e.g. `"tag.Location":
  ["Dallas"]`. Values within a category are ORed; categories are ANDed.
- `plugin_id`: integer array, singular name. `cve_id`: at most 200 values.
  `plugin_family`: case-sensitive.
- `network_id`: the default network is `00000000-0000-0000-0000-000000000000`.
- `source`: for example `AGENT`, `NESSUS`, `NNM`, `AGENT_RUNTIME`.
- `severity_modification_type`: case-sensitive `NONE`, `RECASTED`, `ACCEPTED`.
- Range filters (`vpr_score` 0.1–10, `epss_score` 0–100 as a percentage,
  `cvss4_base_score` 0–10, `time_taken_to_fix` in seconds) take `{"gte": …, "lte": …}`, or
  `eq`/`neq` arrays. Don't combine `eq` with the inequality operators.
- `zero_day`: true/false, derived from the plugin's CVEs. A plugin with no CVEs matches
  neither value; one with several CVEs can match both.
- `properties` (top level, since 2026-08-03): list the fields you want, which can make
  exports much smaller.
  - `id`, `asset.id` and `definition.id` are always included.
  - An unknown property returns 400 `BAD_REQUEST_UNKNOWN_PROPERTY`.
  - Output uses the full-export field names: `finding_id`, `asset.hostname`, `plugin.name`,
    `first_found`.
- `include_plugin_output` (top level, default `true`, since 2026-07-23): set `false` to drop
  plugin output.
- **Removed:** the `vpr_v2_score` filter and the `plugin.vpr_v2` field were removed on
  2026-10-01, and both now return 400 `BAD_REQUEST_UNKNOWN_PROPERTY` in a request. Use
  `vpr_score` and `plugin.vpr`, which now carry VPR v2.
  - In VM findings, `plugin.vpr` holds `score`, `updated` and `drivers`, plus the v2
    fields: `cve_id`, `vpr_percentile` (0–100), `vpr_severity`, `exploit_probability`
    (0–1), `exploit_code_maturity`, `on_cisa_kev`, `in_the_news_intensity_last_30`,
    `in_the_news_recency`, `malware_observations_intensity_last_30` and
    `malware_observations_recency`. Note the underscore in `last_30`.
  - VM `plugin.vpr` also has `exploit_chain`, `in_the_news_sources_last_30`,
    `threat_summary`, `remediation`, `targeted_industries` and `targeted_regions`. A full
    export **omits these when they're empty**, so treat them as optional. Selecting them with
    `properties` returns them even when empty.
  - WAS findings' `plugin.vpr` always has `score`, occasionally `drivers` and `updated`, and
    none of the v2 fields.
  - The *property selection* names `vpr_v2` and `vpr_v2_drivers_<name>` are still accepted in
    VM `properties`. `vpr_v2` and `definition.vpr.score` both return `plugin.vpr.score`, and
    `vpr_v2_drivers_<name>` returns `plugin.vpr.<name>`. WAS accepts `vpr_v2` but rejects the
    `vpr_v2_drivers_*` names.
  - In testing, a `properties` array of 147 names was accepted and 148 was rejected with
    `400 BAD_REQUEST_INVALID_VALUE`, which isn't documented. Select fewer properties if you
    hit it.

### The status response echoes filters differently

Tag filters come back as `"tags": {"Location": ["Dallas"]}`. The echo can also include
filters you didn't send and omit some you did. Don't compare the echo with your request to
decide whether a job matches.

## Asset exports

- **`chunk_size` is required**, from 100 to 10,000. **Out of range returns 400.** With
  `include_resource_tags`, the maximum is 1,000. Tenable doesn't recommend more than 5,000,
  because errors become more likely above it. Omitting it
  returns 400 "A non-zero chunk_size must be provided".
- Use **v2** (`/assets/v2/export`) for new code. It adds the `since` and `types` filters
  (`host` by default; `webapp` for WAS assets) and omits empty properties. **v2 doesn't
  support `tag.<Category>` filters**; use v1 when you need to filter on tags.
- Timestamp filters (`created_at`, `updated_at`, `deleted_at`, `terminated_at`,
  `first_scan_time`, `last_authenticated_scan_time`, `last_assessed`) mean "later than" the
  Unix time.
- `is_licensed` omitted returns licensed and unlicensed assets.
- Keep assets in sync by `id`, not by IP address or hostname.
- `acr_score` and `exposure_score` are deprecated (2025-08-25) and missing from v2. Use
  `ratings.acr.score` and `ratings.aes.score`.

## Compliance export

- **Send a JSON body**, even `{}`. With no body the API returns `415`.
- `num_findings`: default 5,000, range 50–10,000, clamped.
- Tags: **`"tags": [{"category": "Location", "values": ["Dallas"]}]`**. The `tag.<Category>`
  key form isn't accepted here.
- `first_seen` must be paired with `last_seen`. `since` is based on `indexed_at`.
- `compliance_results`: `PASSED`, `FAILED`, `WARNING`, `SKIPPED`, `ERROR`, `UNKNOWN`.
  `state`: `OPEN`, `REOPENED`, `FIXED`.
- The data is the latest aggregated audit result per check, not per-scan results. A finding
  is identified uniquely by `asset_uuid` + `compliance_full_id` + `audit_file`.

## WAS findings export

The request shape and the 30-day default window are the same as the vuln export, except:

- Severity values are **uppercase** (`INFO` … `CRITICAL`).
- The plugin filter is **`plugin_ids`** (plural).
- WAS-specific filters: `asset_uuid`, `asset_name`, `ipv4s` and `owasp_*`.

Two different things in pyTenable are both called WAS export: `tio.exports.was()` is this
API, while `tio.was.export()` is a legacy helper that walks scan results and returns a
different shape.

## Joining and reconciling

- Vuln `asset.uuid` = asset export `id`. Apart from `asset.uuid`, the `asset` object inside
  a finding is a best guess kept for compatibility. Take asset details from the asset export.
- The `plugin` object in a finding is only as current as the finding's last observation.
- **Findings on deleted or terminated assets never become FIXED.** Run periodic asset
  exports with `deleted_at` / `terminated_at` set to your last sync time, and retire those
  assets' findings yourself.

## pyTenable (`tio.exports`)

```python
iterator = tio.exports.vulns(
    since=last_sync,              # int epoch seconds or datetime
    num_assets=1000,              # pyTenable default is 500
    include_unlicensed=False,     # pyTenable default is True
    severity=['medium', 'high', 'critical'],
    tags=[('Location', ['Dallas', 'Austin'])],
    adopt_existing=False,         # raise on a 409 instead of adopting a job with other filters
)
for finding in iterator:          # plain dicts
    ...
```

- Methods are keyword-only, and unknown filter names raise `TypeError`/`ValidationError`.
  The request models forbid extra fields.
- **Defaults differ from the API:** `vulns()` and `was()` send `num_assets=500` and
  `include_unlicensed=True`.
- **`vpr_v2_score=` is still accepted** by `vulns()` and `was()`, but the API removed the
  filter and returns 400. Use `vpr_score=`.
- **`adopt_existing=True` is the default.** On a 409, pyTenable logs a warning and adopts the
  running job, which may have different filters.
  - This only works for vulns and WAS. A duplicate asset export returns 429, which pyTenable
    retries as a rate limit, waiting `retry-after` each time. That's about 4 minutes, after
    which it raises `TooManyRequestsError` unless the first job finished in the meantime.
- `compliance(state=…)` takes `OPEN`, `REOPENED` and `FIXED`. Its type hint lists severity
  values, but the model validates states, and so does the API.
- Tags are `[('Category', 'Value')]` or `[('Category', ['V1', 'V2'])]`. pyTenable converts
  them to each export's format. `assets_v2()` has no `tags` parameter.
- `uuid=` reattaches to an existing job without a new POST. `iterator=None` returns the
  export UUID instead of an iterator.
- `when_done=True` withholds chunks until the job is `FINISHED`. It's a boolean, not a
  callback. **`exports.assets()` (v1) accepts it but ignores it.**
- `timeout=` only applies while the job is `QUEUED`. When it's exceeded, the job is
  cancelled and `TioExportsTimeout` is raised. The clock starts when the iterator is created,
  which matters when reattaching with `uuid=`. Compliance jobs are never `QUEUED`, so
  `timeout=` never fires for them.
- **The iterator stops only on `FINISHED` (or raises on `ERROR`).** A job cancelled by
  someone else is polled forever, every 30 seconds at most. Enforce your own overall
  deadline in long-running jobs.
- `max_items` and `max_pages` aren't honored by export iterators.
- `iterator.run_threaded(func, kwargs=None, num_threads=2)` calls
  `func(data=…, export_uuid=…, export_type=…, export_chunk_id=…, version=…, **kwargs)`. It
  returns a list of futures; call `.result()` on each to surface exceptions. An iterator can
  be used either serially or threaded, not both.
- A chunk that fails JSON decoding is retried 3 times, then returned as `[]` with only a
  warning. Count findings per chunk if completeness matters.
- Fixes in 26.10.1 (not in 26.8.1 or earlier):
  - Tag filters with list values work. Earlier versions silently dropped them.
  - The compliance tag format is correct.
  - `epss_score` validation accepts 0–100.
  - `properties=` is available.
  - New filters: `include_plugin_output`, `include_software_vulns`, `zero_day`,
    `software_vulns_potential` and `software_vulns_potential_reasons`.

  Upgrade with `pip install -U pytenable`.
