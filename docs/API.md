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

A job begins without blocking the HTTP request. Poll about once per second. Do not resubmit while waiting.

## Poll a scan

`GET /api/search/{id}` → HTTP **200**

```json
{
  "id":"opaque-job-id",
  "status":"completed",
  "message":"Search completed. Matches are unverified page occurrences, not confirmed breaches.",
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

Job states: `queued` → `running` → `completed` or `failed`. While queued/running, `result` and `error` are null. On failure, `result` is null and `error` is a readable string. Stop polling on either terminal state. A scan exceeding its time limit becomes `failed`; individual blocked or broken sites are represented in the completed result instead.

Per-tool statuses: `success`, `no_match`, `blocked`, `error`, `manual_review`. `total_matches` counts visible content occurrences once, excluding forms and navigation. Search-engine pages are `manual_review` with zero matches: echoed queries do not establish an account or exposure. `source_url` is the original catalog URL and `final_url` records the visited page after redirects. `tools_with_matches` counts tool/identifier pairs, not unique people or breaches. `matches` contains only pairs with positive occurrence counts. By default every relevant tool is searched, and counts vary by identifier type. An optional configured cap applies per identifier; `tool_limit_per_query` is null when unlimited. The summary describes only attempted tools.

Jobs expire one hour after finishing, with at most 64 jobs retained and up to 8 queued/running. Restarting the API loses all jobs. Results contain submitted identifiers; job IDs should be treated as private.

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
| `OSINT_CONCURRENCY` | `3` | Browser pages searched simultaneously |
| `OSINT_DELAY` | `0.2` | Delay after each tool search in seconds |
| `OSINT_PAGE_WAIT_MS` | `2500` | Wait after navigation before inspection |

The test Compose overlay supplies a local catalog and pages. Normal Compose uses the live catalog and external sites. Server command: `uvicorn SecurityApp.api:app --host 0.0.0.0 --port 8000` (one worker).
