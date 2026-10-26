# Authentication, base URLs and pyTenable clients

Sources: [Authorization](https://developer.tenable.com/docs/authorization), each API spec's
`securitySchemes` on developer.tenable.com, and the pyTenable source (26.10.1).

## Headers and base URLs (raw HTTP)

| Product | Base URL | Header and value |
|---|---|---|
| Vulnerability Management (VM), Web App Scanning, Tenable One / Exposure Management, PCI ASV | `https://cloud.tenable.com` (FedRAMP customers use the host given in their onboarding documentation) | `X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>` |
| Security Center (Tenable.sc) | The customer's own host, path `/rest/…` | `X-APIKey: accessKey=<ACCESS_KEY>; secretKey=<SECRET_KEY>` (singular `APIKey`). API keys need SC 5.13 or later |
| Nessus / Nessus Manager | `https://<scanner>:8834` | `X-ApiKeys: accessKey=…; secretKey=…`, or a session token in `X-Cookie: token=<token>` |
| Identity Exposure | The customer's own host, path `/api/…` | `x-api-key: <API key>` |
| OT Security | The customer's own host, GraphQL at `/graphql` | `X-APIKeys: key=<API key>` |
| Attack Surface Management | `https://asm.cloud.tenable.com/api/1.0` | `Authorization: <API key>`. pyTenable sends the raw key with no `Bearer` prefix; the spec doesn't document the value format |
| Cloud Security | The customer's GraphQL endpoint | `Authorization: Bearer <service account secret>` |
| Downloads (tenable.com) | `https://www.tenable.com/downloads/api/v2` | `Authorization: Bearer <token>`. Listing pages needs no auth; only files marked `requires_auth` do |

Notes:

- HTTP header names are case-insensitive. The docs write both `X-ApiKeys` and `X-APIKeys`.
- VM API keys are per user, and a user has one valid key pair at a time. Generating a new
  pair invalidates the old one, which breaks every integration using it. Tenable recommends
  a dedicated user, and therefore a dedicated key, for each integration.
- Rate limits are applied per API key (see `limits-and-retries.md`).

## pyTenable classes

pyTenable reads each credential from a keyword argument first, then from
`<PREFIX>_<PARAM>` in the environment. The URL comes from `url=`, then `<PREFIX>_URL`, then
the class default.

| Class | Import | Credential kwargs → env vars | Default URL | SSL verify default | Default timeout |
|---|---|---|---|---|---|
| `TenableIO` (VM; alias `tenable.vm.TenableVM`) | `from tenable.io import TenableIO` | `access_key`, `secret_key` → `TIO_ACCESS_KEY`, `TIO_SECRET_KEY`; `TIO_URL` | `https://cloud.tenable.com` | on | 120 s |
| `TenableOne` | `from tenable.tenableone import TenableOne` | `access_key`, `secret_key` → **`TO_ACCESS_KEY`, `TO_SECRET_KEY`**; `TO_URL` | `https://cloud.tenable.com` | on | none |
| `TenableSC` | `from tenable.sc import TenableSC` | `access_key`, `secret_key` → `TSC_*`; or `cert=(cert, key)`; or `username`/`password` (deprecated) | none: pass `url=` | **off** | 300 s |
| `Nessus` | `from tenable.nessus import Nessus` | `access_key`, `secret_key` → `NESSUS_*`; or `username`/`password` | none | **off** | none |
| `TenableIE` | `from tenable.ie import TenableIE` | **`api_key`** (singular) → `TIE_API_KEY` | none | on | none |
| `TenableOT` | `from tenable.ot import TenableOT` | `api_key` → `TOT_API_KEY` | none | **off** | none |
| `TenableASM` | `from tenable.asm import TenableASM` | `api_key` → `TASM_API_KEY` | none | on | none |
| `Downloads` | `from tenable.dl import Downloads` | `api_token` → `TDL_API_TOKEN` | `https://www.tenable.com` | on | none |
| `CloudSecurity` | `from tenable.cloudsecurity import CloudSecurity` | `api_key` → `TCS_API_KEY`; `TCS_URL` | none | `verify=True` (note the name) | 300 s |

### Traps

- **Missing credentials don't raise.** If no auth method has every parameter set,
  pyTenable emits `AuthenticationWarning` and continues unauthenticated, and every call then
  fails with 401/403. To fail fast:

  ```python
  import warnings
  from tenable.errors import AuthenticationWarning
  warnings.simplefilter('error', AuthenticationWarning)  # raise instead of warn
  ```

  `Downloads` warns with a plain `UserWarning` instead, so check its token yourself.

- **Unknown keyword arguments are ignored** for every class except CloudSecurity, including
  typos in credential names (`acess_key`, `api_keys`) and in options such as `verify=` for
  `ssl_verify=` or `timeout_s=` for `timeout=`.
- **Credentials can mix sources.** `TenableIO(access_key=X)` pairs X with whatever
  `TIO_SECRET_KEY` holds. A leftover `TIO_URL` in the environment silently overrides the
  default URL.
- **Don't use `TenableSC` positionally.** Its first positional argument is the deprecated
  `host`, so `TenableSC('https://sc.example.com')` builds `https://https://sc.example.com:443`.
  Always use `TenableSC(url='https://sc.example.com', access_key=…, secret_key=…)`.
- **Security Center reads its version before authenticating.** With keys, the first request
  is an unauthenticated `GET /rest/system`. Mock it in tests. Below version 5.13,
  `tenable.errors.ConnectionError` is raised.
- **No trailing slash.** `url='https://host/'` produces `https://host//path` on every request.
- **An invalid URL raises the built-in `ConnectionError`**, not `tenable.errors.ConnectionError`.
- **Disabling SSL verification is process-wide.** With `ssl_verify=False` (the default for SC,
  Nessus and OT), pyTenable also suppresses urllib3's "Unverified HTTPS request" warning for
  the whole process. Pass `ssl_verify=True` with a trusted CA bundle in production.
- **Set a timeout** on every class that has none by default: `TenableOne(…, timeout=120)`.
  Otherwise a stalled connection hangs forever.
- **Credential priority for SC** is keys > certificate > session. With `TSC_ACCESS_KEY` set
  in the environment, `cert=` is ignored.
- **SC certificate auth on Windows.** `p12_cert=` writes temporary PEM files that Windows
  can't reopen by name, so convert the certificate to PEM and pass `cert=(cert_path, key_path)`.
- **Logging can expose secrets.** At DEBUG level pyTenable logs every request's method, URL,
  parameters and JSON body. Only SC's `token` and `credential` paths are masked, so a Nessus
  username/password login appears in clear text. Don't enable DEBUG for `tenable` in
  production.
