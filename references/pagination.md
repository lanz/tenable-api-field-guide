# Pagination by API

Each API pages differently. Use the scheme for the endpoint you're calling, and check the
endpoint's reference page when it isn't listed here.

| API / endpoint | Scheme | Limits and envelope |
|---|---|---|
| VM `GET /scans` (`scans-list`) | Not paginated in the published spec. Filters: `folder_id`, `last_modification_date` (means scan *execution* time, not configuration edits), `started_from`, `started_to` (exclusive; both look only at each scan's latest run) | Response `{scans, folders, timestamp}`. **Code defensively**: if a `pagination` object appears, page with `limit`/`offset` until `pagination.total` |
| VM `GET /assets` (`assets-list-assets`) | None | **At most 5,000 assets.** Use the asset export for more |
| VM workbenches | None | **At most 5,000 records**, data under 450 days old. Use exports |
| VM `GET /plugins/plugin` (`io-plugins-list`) | `size` + `page` (1-based) | `size` default 1,000, max 10,000. Response has `total_count`. `last_updated` takes `YYYY-MM-DD`, not epoch |
| Platform lists (tags, credentials, exclusions, agent group details, audit log) | `limit` + `offset` (+ `sort`) | Defaults and maximums vary: credentials max 300; exclusions default 200, max 500; agent groups default 50, max 5,000; audit log default 50, max 10,000, envelope `pagination{offset,limit,count,total}` |
| `GET /tags/values` | `limit` + `offset`; filter with `f=field:op:value` (repeatable), `ft=and\|or`, `w`/`wf` for wildcard | Default limit 5,000. A value containing `:` didn't match `f=value:eq:<value>` in testing; filter on `category_name` and compare values locally (recipe 4) |
| WAS v2 search/list | Query `limit` + `offset` + `sort=field:asc\|desc` | **Max 200**, default 10. Envelope `pagination{total,limit,offset,sort[]}` |
| Tenable One / Exposure Management inventory exports | Query `sort=field:direction` | No default order is documented, and results without `sort` came back in no recognizable order. Pass `sort` when order matters |
| Tenable One / Exposure Management inventory search | **Query** `offset`, `limit`, `sort=field:asc\|desc`; `filters`/`query` in the POST body | `inventory-assets-search` max 1,000; `inventory-findings-search` max 10,000. Envelope `pagination{total,offset,limit,sort}` |
| Tenable One attack-path searches (`apa-attack-paths-search`, `apa-attack-techniques-search`) | **Query** `offset`, `limit`, `sort`; the POST body **is** the filter: one `{property, operator, value}`, or `{operator, value: [filters…]}` for several. No `filters` wrapper | `limit` **min 100**, max 10,000 |
| Tenable One exposure-view cards (`exposure-view-cards-search`) | `GET` with query `offset`, `limit` | Max 25 |
| PCI ASV lists | `limit` + `offset` + `sort` | Envelope `pagination{total,offset,limit,sort[]}` |
| ASM `POST /inventory` | `limit` (1–10,000) + `offset`, **or** `after=<last asset id>` for deep paging | With `after`, `offset` is ignored and `total`/`stats` are omitted. Recommended page size 2,000–10,000 |
| Identity Exposure | `page` + `perPage` (numeric **strings**), or `limit` on some endpoints | Per endpoint |
| Security Center analysis (`POST /rest/analysis`) | `query.startOffset` + `query.endOffset` | Response `totalRecords`, `returnedRecords`. Pages default to 1,000 in pyTenable |
| Cloud Security (GraphQL) | Cursor: `first` + `after` | Pass `after: null` first, then `pageInfo.endCursor` while `pageInfo.hasNextPage` |
| Downloads | None | — |

## Rules

- **Stop on the envelope, not on page size.** Use `total` when it's given, and also stop on
  an empty page so a miscount can't loop forever.
- **Sort stability:** list endpoints that sort by a mutable field (for example last
  modification) can shift under you while you page. De-duplicate by ID, and compare your
  count with `total` at the end.
- **pyTenable gaps:**
  - `tio.scans.list()` sends no paging parameters, so it returns only the first page of a
    paginated response. Use `tio.get('scans', params={'limit': 200, 'offset': n}).json()`
    when you need paging.
  - `tio.assets.list()` is the 5,000-record endpoint.
  - Tenable One `inventory.*.list()` returns one page model (`.data`, `.pagination`), and
    you page with `offset`/`limit`. Iterate `page.data`, not the page itself.
