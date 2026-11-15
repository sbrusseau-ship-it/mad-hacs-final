# Frontend/backend contract v1

All paths are relative to the app origin. The frontend sends JSON and uses the same origin Nginx/Vite proxy, so no CORS configuration is needed.

## Submit a scan

`POST /api/search`, `Content-Type: application/json`

```json
{"identifiers":{"email":"sample@example.com","username":"sample_user"}}
```

Send one or more of these keys; omit disabled or empty fields. Every value must be a nonempty string, trimmed by the server, of at most 256 characters, with no control characters. Unknown keys and extra top-level keys are rejected.

| Key | Validation / scanner type |
| --- | --- |
| `email` | Email address / `email` |
| `username` | Up to 64 characters, no whitespace / `username` |
| `name` | Contains letters, no numbers / `name` |
| `ssn` | Nine digits or `XXX-XX-XXXX` / `ssn` |
| `phone` | Ten-digit US number, optional separators / `phone_us` |
| `address` | Contains letters / `address` |
| `ip` | Valid IPv4 or IPv6 / `ip_address` |

Field names determine query types explicitly; they are not inferred from the values. SSNs are transmitted when selected and filled, just like other fields.

Success: HTTP **202**

```json
{"id":"opaque-job-id","status":"queued","message":"Search queued."}
```

A job begins without blocking the HTTP request. Subscribe to the event stream below to display results as soon as sources finish. Polling about once per second remains a fallback. Do not resubmit while waiting.

## Poll a scan

`GET /api/search/{id}` → HTTP **200**

```json
{
  "id":"opaque-job-id",
  "status":"completed",
  "message":"Search completed. Results are unverified leads, not confirmed breaches or account ownership.",
  "error":null,
  "result":{
    "summary":{
      "timestamp":"2026-11-15T12:00:00",
      "total_queries":1,
      "queries":[{"value":"sample_user","type":"username"}],
      "total_tools_searched":1,
      "tools_with_matches":1,
      "total_matches":2,
      "two_d_array_size":1,
      "results_by_status":{"success":1,"no_match":0,"blocked":0,"error":0},
      "tool_limit_per_query":null
    },
    "results":[{
      "input_value":"sample_user",
      "input_type":"username",
      "tool_name":"Example directory",
      "category":"Username",
      "url_searched":"https://example.com/search?q=sample_user",
      "status":"success",
      "match_count":2,
      "match_details":["Visible content occurrences: 2"],
      "error":null
    }],
    "matches":[["sample_user","Example directory"]]
  }
}
```

Job states: `queued` → `running` → `completed` or `failed`. While queued or loading the catalog, `result` is null. During scanning, `result` contains the results collected so far, with the same shape as a completed result. `progress` reports `completed_sources` and `total_sources`; `summary.total_tools_planned` is the total for the selected identifier types. On failure, any partial `result` is retained and `error` is a readable string. Stop polling on either terminal state. A scan exceeding its time limit becomes `failed`; individual blocked or broken sites are represented in the completed result instead.

Per-tool statuses: `success`, `no_match`, `blocked`, `error`, `manual_review`. `total_matches` counts visible content occurrences once, excluding forms and navigation. Search-engine pages are `manual_review` with zero matches: echoed queries do not establish an account or exposure. `source_url` is the original catalog URL and `final_url` records the visited page after redirects. `tools_with_matches` counts tool/identifier pairs, not unique people or breaches. `matches` contains only pairs with positive occurrence counts. By default every relevant tool is searched, and counts vary by identifier type. An optional configured cap applies per identifier; `tool_limit_per_query` is null when unlimited. The summary describes only attempted tools.

Jobs expire one hour after finishing, with at most 64 jobs retained and up to 8 queued/running. Restarting the API loses all jobs. Results contain submitted identifiers; job IDs should be treated as private.

## Live results (preferred)

`GET /api/search/{id}/events` → `Content-Type: text/event-stream`

Each SSE `data` message contains a complete `SearchJob` snapshot, including partial `result` and `progress` fields. The initial snapshot arrives immediately; subsequent snapshots are coalesced at up to five updates per second. The stream closes after a `completed` or `failed` snapshot. Ten-second comment heartbeats keep idle connections alive. Reconnecting returns the latest snapshot, so the frontend can replace its state without replaying or duplicating rows. Disconnecting does not cancel the job.

```js
const events = new EventSource(`/api/search/${id}/events`);
events.onmessage = ({ data }) => {
  const job = JSON.parse(data);
  render(job.result, job.progress);
  if (["completed", "failed"].includes(job.status)) events.close();
};
```

Nginx disables proxy buffering for the stream. The app automatically falls back to polling if streaming disconnects, and continues displaying partial results. Eight browser pages run concurrently by default using the shared browser context. Every relevant source is scheduled; no global 30-second cutoff is enabled by default. The per-source deadline prevents an individual site from occupying a slot indefinitely.

## Errors and health

HTTP error body:

```json
{"error":"Check the supplied identifiers.","fields":{"email":"Enter a valid email."}}
```

`fields` is optional. HTTP 400: invalid JSON/fields; 413: body over 16 KiB; 415: wrong content type; 429: queue full; 404: unknown/expired job. Frontend displays the supplied error and restores the form for retry. HTTP errors differ from a job's terminal `failed` status (a successful poll with HTTP 200).

`GET /api/health` → `{"status":"ok"}`. This checks API responsiveness; it does not guarantee third-party sites or the GitHub catalog are reachable.

## Backend configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `OSINT_TREE_URL` | Public OSINT Framework GitHub JSON URL | Tool catalog URL |
| `OSINT_TREE_FILE` | Unset | Local JSON catalog; takes precedence over URL |
| `OSINT_MAX_TOOLS` | `0` | Maximum relevant tools per identifier; 0 searches all relevant tools |
| `OSINT_SCAN_TIMEOUT` | `0` | Active scan time limit in seconds; 0 disables the overall limit |
| `OSINT_CONCURRENCY` | `8` | Browser pages searched simultaneously (1–32), shared across all identifiers |
| `OSINT_SOURCE_TIMEOUT` | `30` | Deadline per source in seconds; a timed-out source becomes an error while the rest continue |
| `OSINT_DELAY` | `0.2` | Delay after each tool search in seconds |
| `OSINT_PAGE_WAIT_MS` | `2500` | Wait after navigation before inspection |

The test Compose overlay supplies a local catalog and pages. Normal Compose uses the live catalog and external sites. Server command: `uvicorn SecurityApp.api:app --host 0.0.0.0 --port 8000` (one worker).

## Username searches with Sherlock

Username is the first identifier and the only one selected by default. A filled `username` starts both the existing browser scanner and the real `sherlock-project==0.16.2` backend concurrently. Other identifier types do not invoke Sherlock. Email addresses are not converted to usernames.

Sherlock runs site-specific username availability checks using HTTP requests in an isolated worker process. Its results enter the same SSE stream and polling response as browser results. Each result has `backend: "browser" | "sherlock"`; Sherlock rows are named `Sherlock · <site>` and link to the checked profile. `Claimed` maps to `success` and contributes one potential match, `Available` maps to `no_match`, WAF blocks map to `blocked`, and unknown/unsupported username formats map to `error`. A claimed username does not establish account ownership or a breach.

Source totals combine the browser catalog and Sherlock catalog; the planned total updates as each catalog finishes loading. `total_matches` includes one detection for each Sherlock claimed account plus visible-content occurrences from browser checks. Failures in one backend retain the other backend's results. Worker processes are terminated on cancellation, scan timeout or shutdown. No Sherlock text/CSV reports are written.

The browser scanner excludes GitHub repository, raw-content, gist and GitHub Pages documentation links because visiting a project page does not execute its tool. This filter does not remove GitHub profile results produced by Sherlock.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SHERLOCK_CONCURRENCY` | `8` | Outstanding Sherlock site checks, 1–20, separate from the browser's cap |
| `SHERLOCK_REQUEST_TIMEOUT` | `10` | Per-request HTTP timeout in seconds |
| `SHERLOCK_SITES_URL` | Sherlock's live catalog | Override the Sherlock site manifest URL |
| `SHERLOCK_SITES_FILE` | Unset | Local manifest override, takes precedence over URL |

Sherlock excludes 7Cups, F3.cool and Houzz before planning or scheduling requests. They contribute neither result rows nor planned/searched/hit totals or grader percentages.

The normal catalog honors Sherlock's published false-positive exclusions and standard NSFW filtering. Explicit fixture/custom manifests are used as supplied without fetching remote exclusions. If the live catalog is unavailable, the packaged catalog is used. A worker that produces no events for at least 45 seconds is stopped and reported as a backend error.

## Grader statistics

`result.grade` is calculated by `SecurityApp/GraderCode.py` from current scanner counts and updates with every streamed result. `percent_matches` is `tools_with_matches / total_tools_searched * 100`, rounded to two decimals (zero when no sites have finished). `total_sites` counts finished source/identifier checks; `sites_with_hits` counts checks with positive evidence; `total_matches` is the evidence count. Multiple identifiers/backends can check the same website, so these are source checks, not distinct domains. Search-engine-only entries are not positive hit evidence.

The three headline statistics display `percent_matches`, `sites_with_hits`, and `total_sites`, in that order. Before a scan they show dashes; during a scan they reflect completed source checks.
