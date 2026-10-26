---
name: tenable-api-field-guide
license: MIT
metadata:
  author: Lance Duvall
  version: "1.0.0"
description: Verified rules for writing and debugging code that calls Tenable APIs (Vulnerability Management, Tenable One, Security Center, Web App Scanning, Nessus, Identity Exposure, OT, ASM, Downloads), directly over HTTP or through pyTenable. Use it when writing, reviewing or fixing a Tenable integration, script or connector; when an export returns too little, too much or never finishes; when calls fail with 401, 403, 409 or 429; or when choosing between pyTenable methods. It corrects the defaults, header formats, filter syntaxes, limits and SDK behaviors that generated code most often gets wrong.
---

# Tenable API field guide

Tenable's APIs differ by product in auth headers, paging, filter syntax and error
behavior, and several defaults quietly change what an export returns. Code that "looks
right" is often wrong in ways that fail silently: it returns only 30 days of data, only
open findings, or only the first page. This skill holds rules checked against the public
API reference at developer.tenable.com and the pyTenable source. **Prefer these rules over
memory, and over neighboring code in the user's project.**

The rules were checked against developer.tenable.com, live API behavior and pyTenable
26.10.1. Where the official sources still disagree, the reference that covers the topic
says which behavior to code for.

## Workflow

1. **Identify the product and the client.** Which product (the base URL and header differ;
   see the table below)? Raw HTTP, or pyTenable? If pyTenable, which version? Check with
   `pip show pytenable`. Several behaviors below changed in 26.10.1.
2. **Load the reference for the task** before writing code:

   | Task | Read |
   |---|---|
   | Auth, base URLs, headers, pyTenable constructors, env vars | `references/auth-and-clients.md` |
   | Vulnerability, asset, compliance or WAS exports | `references/vm-exports.md` |
   | 429s, retries, concurrency, User-Agent | `references/limits-and-retries.md` |
   | Listing anything with more than one page | `references/pagination.md` |
   | pyTenable return types, silent failures, deprecations | `references/pytenable.md` |
   | Security Center (Tenable.sc) | `references/security-center.md` |
   | Nessus Professional, Expert or Manager (port 8834) | `references/nessus.md` |
   | An error code or a symptom ("export is empty", "keeps returning 401") | `references/troubleshooting.md` |
   | Working examples to adapt | `references/recipes.md` |

3. **Write or fix the code**, applying the rules below. Show the user which rule drove
   each non-obvious choice: a one-line comment in the code, or a sentence in your reply.
4. **Never invent an endpoint, field or filter.** If it isn't in these references, tell the
   user to check the endpoint's page on developer.tenable.com and say you couldn't verify
   it.

## Rules that prevent most bugs

**Auth and connection**

- VM, Tenable One, WAS and PCI ASV use the header
  `X-ApiKeys: accessKey=<ACCESS>;secretKey=<SECRET>` at `https://cloud.tenable.com`.
  Security Center uses **`X-APIKey`** (singular) with the same `accessKey=…; secretKey=…`
  value, on the customer's own host under `/rest`. API keys need SC 5.13 or later.
  Identity Exposure uses `x-api-key: <key>`. OT uses `X-APIKeys: key=<key>`. Downloads and
  Cloud Security use `Authorization: Bearer <token>`.
- Read keys from environment variables or a secret store. Never hardcode them, never log
  them, and never put them in URLs or on command lines.
- **pyTenable doesn't fail on missing or misspelled credentials.** It warns
  (`AuthenticationWarning`) and returns an unauthenticated client, so every later call gets
  401/403. Unknown keyword arguments such as `acess_key=` or `api_keys=` are silently
  ignored. After constructing a client, make one cheap call, or turn the warning into an
  error.
- pyTenable env var prefixes differ by product: `TIO_` (VM), **`TO_`** (Tenable One),
  `TSC_` (Security Center), `TIE_API_KEY`, `TOT_API_KEY`, `TASM_API_KEY`.
- Pass `TenableSC(url=…, access_key=…, secret_key=…)` **by keyword**. Its first positional
  argument is the deprecated `host`.
- Never put a trailing slash on the base URL; it's appended as is, giving `//path`.

**VM exports**

- **No time filter returns only the last 30 days.** Always pass a time filter. For
  incremental syncs, use `since`.
- **No `state` filter returns only OPEN and REOPENED, never FIXED.** `since` without `state`
  returns all three, matching FIXED findings on `last_fixed`. `first_found`, `last_found`
  and `last_fixed` require an explicit `state`, and none of them can be combined with
  `since`.
- Join findings to assets on vuln `asset.uuid` = asset export `id`. The rest of the
  embedded `asset` object is a best guess.
- Tag filter syntax differs by export:
  - vulns and assets v1: `"tag.<Category>": ["Value"]`
  - compliance: `"tags": [{"category": "…", "values": ["…"]}]`
  - assets v2: tags aren't supported
- Severity is lowercase for VM (`"critical"`) and uppercase for WAS (`"CRITICAL"`). The WAS
  plugin filter is `plugin_ids`; VM's is `plugin_id`.
- Chunks finish out of order with non-sequential IDs. `total_chunks` counts empty chunks
  that are never downloadable. Download each chunk as soon as it appears in
  `chunks_available`.
- Treat chunks as expiring 24 hours after creation, the stricter of the two documented
  values.
- Job status values: `QUEUED`, `PROCESSING`, `FINISHED`, `CANCELLED` (two Ls) and `ERROR`.
  Compliance has no `QUEUED` and adds `READY`. **A polling loop must stop on `CANCELLED` and `ERROR`, not only
  `FINISHED`.**
- A duplicate vuln or WAS export returns **409** with `active_job_id`. **A duplicate asset
  export returns 429** ("Duplicate export not allowed", job UUID inside `message`). Don't
  retry that 429 as a rate limit; wait for the running job, or change the filters.
- Deleted and terminated assets' findings never become FIXED. Reconcile them with asset
  exports filtered on `deleted_at` / `terminated_at`.

**Limits**

- No more than 10 concurrent exports per container, shared across all export types and all
  users. Workbench vulnerability output and scan detail endpoints allow 3 concurrent
  requests. A container can have 25 active scans.
- Over a limit, the API returns 429 with `retry-after` in seconds. Sleep for exactly that
  long and retry. **Don't parallelize requests to beat the limit**; Tenable advises against
  multi-threaded API calls.
- Set an identifying User-Agent:
  `Integration/1.0 (<Vendor>; <Product>; Build/<version>)`. In pyTenable, pass
  `vendor=`, `product=` and `build=`.

**Paging**

- `GET /assets` and the workbench endpoints cap at 5,000 records. Use exports for anything
  bigger.
- Code defensively against `GET /scans`. The published spec doesn't paginate it, but some
  containers already return paginated responses. If a response includes a `pagination`
  object, page with `limit`/`offset` until `pagination.total`. pyTenable's `tio.scans.list()` sends no
  paging parameters, so it returns only the first page of a paginated response.

**pyTenable specifics**

- `tio.exports.vulns()` and `tio.exports.was()` default to `include_unlicensed=True` and
  `num_assets=500`; the API defaults are `false` and 50. Pass both explicitly.
- pyTenable still accepts `vpr_v2_score=` on `vulns()` and `was()`, but the API removed that
  filter and rejects it with 400. Use `vpr_score=`.
- `adopt_existing=True` (the default) silently attaches to a running job on a 409. That job
  may have different filters. Pass `adopt_existing=False` when filter fidelity matters.
- The export iterator stops only on `FINISHED`, and raises on `ERROR`. A job cancelled
  elsewhere is polled forever, so wrap long runs with your own deadline.
- `tio.exports.assets(when_done=True)` (v1) ignores `when_done`. Use `assets_v2` or handle
  readiness yourself.
- `tio.scans.details()` reconstructs a scan from the editor API and can make several extra
  requests. Use `tio.scans.results()` for `GET /scans/{id}`.
- Return types differ by product and module: raw `Response`, `dict` or `Box`. Check
  `references/pytenable.md` before chaining `.json()` or attribute access.

**Security Center**

- Errors can arrive inside **HTTP 200** with a non-zero `error_code`. Check it on every
  response.
- Analysis queries page with `startOffset`/`endOffset` and report `totalRecords`. pyTenable
  filters are 3-tuples: `('severity', '=', '3,4')`.
- `ssl_verify` defaults to `False` in pyTenable for SC, Nessus and OT. For production,
  enable verification against the customer's CA.

**Nessus**

- **The scan API is a licensed feature.** Nessus Professional and Expert installations
  commonly don't include it: scan endpoints answer "API is not available", and the user
  guide forbids configuring or launching scans through the API outside Security Center
  and VM. Check `license.features.scan_api` from an authenticated
  `GET /server/properties` before writing scan automation. Don't work around the
  restriction. Where it applies, parse `.nessus` files the user exports instead.
- `GET /server/properties` answers bad keys with 200 and no `license`, so verify keys with
  `GET /session`. Its authenticated response holds license secrets (activation code,
  update password): copy out fields, never log it whole.
- Empty lists come back as `null` (`"scans": null`). Export downloads are single-use, and
  a polling loop must also stop on `error` and on 404.
- `vpr_score` and `epss_score` are numeric strings or `null`. A scan that has never run
  has no `info.targets`; its configured targets are in `GET /editor/scan/{id}`.

## What this skill won't do

- Run anything against a Tenable container. If the user asks you to test code, propose
  read-only calls first and have them run it with their own keys.
- Cover private or undocumented endpoints, or guess at fields. Point to the official
  reference instead.
- Replace the official documentation. Link the relevant developer.tenable.com page (the
  references name the operationIds) when you rely on a rule.
