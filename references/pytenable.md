# pyTenable behaviors that surprise integrators

Verified against pyTenable 26.10.1 (`pip install -U pytenable`). It requires Python 3.11 or
later. Import exceptions from `tenable.errors`. The SDK vendors its HTTP layer, so don't
install or patch `restfly` separately.

## Return types

Each client returns one of three things, depending on product and module:

- the raw `requests.Response`
- a `dict`/`list`
- a `Box` (a dict subclass with attribute access)

| Client | Typical return |
|---|---|
| `TenableIO` | Mixed. Older modules return `dict`/`list` (`.json()` applied internally); newer modules (`scans`, `exports`, `access_control` …) return Box. `scans.list()` returns a BoxList, while `scans.results()` returns a plain `dict` |
| `TenableSC` | Usually the `response` member of the SC envelope, as a `dict`. **`sc.scans.list()` returns `{'usable': [...], 'manageable': [...]}`**, not a list |
| `Nessus`, `TenableIE`, `TenableOT` | `dict`/`list` |
| `TenableOne`, `TenableASM`, `TenableAPA`, `Downloads` | Box, often wrapped in pydantic models (Tenable One) |
| Low-level `client.get('path')` | Whatever the platform default is: a raw `Response` for TenableIO and TenableSC, so call `.json()` |

Rules:

- **Index with `obj['key']`** when you're unsure. It works on dicts and Boxes alike;
  attribute access only works on Box.
- **Don't pass `box=True` or `conv_json=True` to `TenableIO` or `TenableSC`.** Their legacy
  methods call `.json()` on the platform's raw `Response` and break.
- Responses that aren't JSON (file downloads) always come back as the raw `Response`. For
  streamed downloads on a Box-default client, pass `box=False`.

## Silent failures

- Missing or misspelled credentials produce an unauthenticated client with only an
  `AuthenticationWarning`. Unknown kwargs are ignored. See `auth-and-clients.md`.
- `scrub()` cleans IDs before they go into URL paths: it keeps `[A-Za-z0-9-_%@:#]` and
  **silently drops everything else, including `.` and `/`**. An ID containing a dot is
  mangled, with only a log warning.
- The success check is `200 <= status < 299`, so a 299 status is treated as an error.
- Python hides `DeprecationWarning` outside `__main__` by default, so pyTenable's deprecation
  notices are invisible unless you enable them (`python -W default::DeprecationWarning`).

## VM (`TenableIO`)

- `tio.scans.list(folder_id=None, last_modified=None, *, started_from=None, started_to=None)`
  makes one `GET /scans`.
  - It doesn't page (see `pagination.md`).
  - A `last_modified` `datetime` is converted with `time.mktime(dt.timetuple())`, which
    drops any timezone, so even an aware UTC datetime is read as **local time**. Pass an int
    epoch to be safe.
  - `folder_id=0` is dropped because the check is falsy.
- **`tio.scans.details(id)` isn't `GET /scans/{id}`.** It reconstructs a create/configure
  document from the editor API, making one `GET /editor/scan/{id}` plus one request per
  plugin family in mixed state. Use `tio.scans.results(id)` for `GET /scans/{id}`, or
  `tio.get(f'editor/scan/{id}').json()` for the raw configuration.
- **Legacy filter definitions are cached per process for 60 s, across instances.** In a
  multi-tenant process, filter validation in the legacy modules (scans, workbenches, agents,
  assets) uses whichever container filled the cache first.
- Deprecated, with replacements:

  | Deprecated | Use instead |
  |---|---|
  | `tio.workbenches` | `tio.exports` |
  | `tio.exports.initiate_export()` | The per-type method with `iterator=None` |
  | `tio.scans.results(history_uuid=)` | `history_id=` |
  | `tio.session` | `tio.users` |

## Exports

See `vm-exports.md` § pyTenable: defaults that differ from the API, `adopt_existing`, the
ignored `when_done` on assets v1, the endless poll of a cancelled job, and chunk decode
failures returning `[]`.

## Tenable One (`TenableOne`)

- **Env vars are `TO_ACCESS_KEY` / `TO_SECRET_KEY`**, not `TIO_*`.
- Sort is sent as `sort=<field>:<direction>`, but **only when both `sort_by` and
  `sort_direction` are given**. Otherwise sorting is silently dropped.
- `SortDirection` and `QueryMode` in `tenable.tenableone.inventory.schema` are plain
  `Enum`s. Pass `SortDirection.DESC`, not `'desc'`: assets, software and tags call `.value`
  and raise `AttributeError` on a string.
- **Inventory findings send the text query only when both `query_text` and `query_mode` are
  set**; with just `query_text`, it's silently dropped. Assets send it when either is set.
- `inventory.<resource>.list()` and `tags.list()` return a single page model with `.data` and `.pagination`.
  Iterate `.data`, and page with `offset`/`limit`.
- Response models are pydantic, so a required field the server omits raises
  `pydantic.ValidationError`.
- `attack_path.findings.list()` names its sort parameter **`sort_filed`** (a misspelling
  kept for compatibility), with `sort_order`. `attack_path.vectors.list()` uses `sort_field`
  and `sort_order`.
- Both `list()` methods wrap GET list endpoints that aren't in the published API reference.
  The documented replacement is `POST /api/v1/t1/apa/top-attack-paths/search`
  (`apa-attack-paths-search`). In 26.10.1, `attack_path.vectors.top_attack_paths_search()`
  posts to `api/v1/t1/top-attack-paths/search` (no `apa/`), which returned 403 in testing
  where the documented path returned 200. Until that's fixed, call the documented path
  directly: `tenable_one.post('api/v1/t1/apa/top-attack-paths/search', params={...}, json={...})`.
  There's no pyTenable method for `apa-attack-techniques-search`.

## Errors

- Validation errors depend on the module's generation:
  - `TypeError` / `tenable.errors.UnexpectedValueError` (legacy `_check`)
  - `pydantic.ValidationError` (exports, Tenable One)
  - `marshmallow.ValidationError` (Identity Exposure, APA)
- HTTP errors map to `tenable.errors` classes:
  - `BadRequestError` 400
  - `UnauthorizedError` 401
  - `ForbiddenError` 403
  - `NotFoundError` 404
  - `RequestConflictError` 409
  - `InvalidContentError` 422
  - `TooManyRequestsError` 420/429
  - `ServerError` 500

  Each exposes `.code` and `.response`.
- **On Security Center, a 403 raises a plain `APIError`**, so `except ForbiddenError` never
  fires there.
- `tenable.errors.ConnectionError`, `NotImplementedError` and `PackageMissingError` shadow
  built-in names. Import them qualified (`from tenable import errors`).
