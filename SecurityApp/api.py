"""Noninteractive HTTP boundary for the team's Playwright scanner.

Jobs and personal identifiers live only in memory, expire after one hour, and
are lost on restart. Run one uvicorn worker; job storage is process-local.
"""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import Backend as scanner
from .sherlock_backend import run_sherlock
from .GraderCode import grade_counts


FIELD_TYPES = {
    "email": scanner.InputType.EMAIL,
    "username": scanner.InputType.USERNAME,
    "name": scanner.InputType.NAME,
    "ssn": scanner.InputType.SSN,
    "phone": scanner.InputType.PHONE_US,
    "address": scanner.InputType.ADDRESS,
    "ip": scanner.InputType.IP_ADDRESS,
}
jobs = {}
tasks = set()
scan_lock = asyncio.Semaphore(1)
scanner.log.setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app):
    yield
    for task in list(tasks):
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    tasks.clear()
    jobs.clear()


app = FastAPI(title="CatPhish API", version="1.0.0", lifespan=lifespan)


class ApiError(BaseModel):
    error: str
    fields: dict[str, str] | None = None


class SearchAccepted(BaseModel):
    id: str
    status: Literal["queued"]
    message: str


class ToolResultResponse(BaseModel):
    input_value: str
    input_type: str
    tool_name: str
    category: str
    url_searched: str
    status: Literal["success", "no_match", "blocked", "error", "manual_review"]
    match_count: int
    match_details: list[str]
    error: str | None
    backend: Literal["browser", "sherlock"] = "browser"
    source_url: str | None = None
    final_url: str | None = None


class ScanGrade(BaseModel):
    percent_matches: float
    total_sites: int
    sites_with_hits: int
    total_matches: int


class SearchResult(BaseModel):
    grade: ScanGrade | None = None
    summary: dict = Field(description="Counts, queried values/types, timestamp, status breakdown, and tool_limit_per_query.")
    results: list[ToolResultResponse]
    matches: list[tuple[str, str]] = Field(description="Pairs of input value and tool name for tools with page occurrences.")


class SearchJob(BaseModel):
    id: str
    status: Literal["queued", "running", "completed", "failed"]
    message: str
    result: SearchResult | None
    error: str | None
    progress: dict[str, int] | None = None


def error(message, status=400, fields=None):
    body = {"error": message}
    if fields:
        body["fields"] = fields
    return JSONResponse(body, status_code=status)


def validate_identifiers(payload):
    if not isinstance(payload, dict) or set(payload) != {"identifiers"}:
        return {}, {"identifiers": "Send an object containing only identifiers."}
    identifiers = payload["identifiers"]
    if not isinstance(identifiers, dict) or not identifiers:
        return {}, {"identifiers": "Provide at least one identifier."}
    clean, errors = {}, {}
    for key, raw in identifiers.items():
        if key not in FIELD_TYPES:
            errors[key] = "Unsupported identifier."
            continue
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 256:
            errors[key] = "Enter a nonempty string of at most 256 characters."
            continue
        value = raw.strip()
        valid = not any(ord(c) < 32 or ord(c) == 127 for c in value)
        if key == "email":
            valid &= bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value))
        elif key == "username":
            valid &= len(value) <= 64 and not any(c.isspace() for c in value)
        elif key == "name":
            valid &= any(c.isalpha() for c in value) and not any(c.isnumeric() for c in value)
        elif key == "ssn":
            valid &= bool(re.fullmatch(r"(?:[0-9]{9}|[0-9]{3}-[0-9]{2}-[0-9]{4})", value))
        elif key == "phone":
            valid &= bool(re.fullmatch(r"(?:\([0-9]{3}\)|[0-9]{3})[ .-]?[0-9]{3}[ .-]?[0-9]{4}", value))
        elif key == "address":
            valid &= any(c.isalpha() for c in value)
        elif key == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                valid = False
        if not valid:
            errors[key] = f"Enter a valid {key}."
        else:
            clean[key] = value
    return clean, errors


def purge_expired():
    now = time.monotonic()
    for job_id, job in list(jobs.items()):
        if job["status"] in {"completed", "failed"} and now - job["updated"] > 3600:
            del jobs[job_id]


def public_job(job):
    return {key: value for key, value in job.items() if key != "updated" and not key.startswith("_")}


async def execute_scan(job_id, identifiers):
    job = jobs[job_id]
    try:
        async with scan_lock:
            job.update(status="running", message="Loading the source catalog.")
            job["_revision"] = job.get("_revision", 0) + 1
            queries = [(value, FIELD_TYPES[key]) for key, value in identifiers.items()]

            tool_limit = int(os.environ.get("OSINT_MAX_TOOLS", "0")) or None
            scan_timeout = float(os.environ.get("OSINT_SCAN_TIMEOUT", "0")) or None

            completed = []
            planned = 0
            backend_plans = {}
            seen_browser = set()

            def publish(data):
                data["summary"]["tool_limit_per_query"] = tool_limit
                job["result"] = {
                    "grade": grade_counts(data["summary"]),
                    "summary": data["summary"],
                    "results": [asdict(result) for result in data["all_results"]],
                    "matches": data["2d_array"],
                }
                count = data["summary"]["total_tools_searched"]
                job["progress"] = {"completed_sources": count, "total_sources": data["summary"].get("total_tools_planned", count)}
                job["message"] = f"Checked {count} of {job['progress']['total_sources']} sources. Results appear as they finish."
                job["_revision"] = job.get("_revision", 0) + 1

            def set_plan(backend, total):
                nonlocal planned
                backend_plans[backend] = total
                planned = sum(backend_plans.values())
                publish(scanner.summarize_results(queries, completed, planned))

            def on_result(result):
                completed.append(result)
                publish(scanner.summarize_results(queries, completed, planned))

            def on_browser_result(result):
                seen_browser.add(id(result))
                on_result(result)

            async def run_browser():
                tree = await asyncio.to_thread(scanner.fetch_osint_tree)
                tools = scanner.flatten_tree(tree)
                if not tools:
                    raise ValueError("No tools in the configured OSINT tree")
                data = await scanner.run_parallel_osint_search(
                    queries, tools, headless=True,
                    max_concurrent=int(os.environ.get("OSINT_CONCURRENCY", "8")),
                    delay_between=float(os.environ.get("OSINT_DELAY", "0.2")),
                    max_tools_per_query=tool_limit,
                    on_plan=lambda total: set_plan("browser", total), on_result=on_browser_result,
                    source_timeout=float(os.environ.get("OSINT_SOURCE_TIMEOUT", "30")),
                )
                if "browser" not in backend_plans:
                    set_plan("browser", data["summary"].get("total_tools_planned", len(data["all_results"])))
                # Also accept adapters that return results without callbacks.
                for result in data['all_results']:
                    if id(result) not in seen_browser:
                        on_browser_result(result)
                return data

            async def run():
                backends = [('browser', run_browser())]
                if 'username' in identifiers:
                    backends.append(('sherlock', run_sherlock(
                        identifiers['username'], lambda total: set_plan('sherlock', total), on_result,
                    )))
                outcomes = await asyncio.gather(*(task for _, task in backends), return_exceptions=True)
                failures = [(name, outcome) for (name, _), outcome in zip(backends, outcomes) if isinstance(outcome, Exception)]
                if len(failures) == len(backends):
                    raise RuntimeError('Search backends failed')
                for name, _ in failures:
                    # A failed backend must not discard results from the other.
                    set_plan(name, sum(row.backend == name for row in completed) + 1)
                    on_result(scanner.ToolResult(
                        identifiers.get('username', ''), 'username', f'{name.title()} backend',
                        'Username', '', 'error', error=f'{name.title()} search could not complete.', backend=name,
                    ))
                return scanner.summarize_results(queries, completed, planned)

            data = await asyncio.wait_for(run(), timeout=scan_timeout)
            if completed:
                data = scanner.summarize_results(queries, completed, planned)
            publish(data)
            job.update(status="completed", message="Search completed. Results are unverified leads, not confirmed breaches or account ownership.")
    except asyncio.TimeoutError:
        job.update(status="failed", message="Search timed out.", error="The scan exceeded its time limit. Try fewer identifiers.")
    except asyncio.CancelledError:
        raise
    except Exception:
        # Do not echo upstream exceptions, which may contain personal identifiers.
        job.update(status="failed", message="Search failed.", error="The scanner could not complete the search. Check backend connectivity and browser installation.")
    finally:
        job["updated"] = time.monotonic()
        job["_revision"] = job.get("_revision", 0) + 1


@app.get("/api/health")
async def health():
    purge_expired()
    return {"status": "ok"}


@app.post(
    "/api/search", status_code=202, response_model=SearchAccepted,
    responses={code: {"model": ApiError} for code in (400, 413, 415, 429)},
    openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"type": "object", "required": ["identifiers"], "additionalProperties": False,
                   "properties": {"identifiers": {"type": "object", "minProperties": 1, "additionalProperties": False,
                       "properties": {key: {"type": "string", "minLength": 1, "maxLength": 256} for key in FIELD_TYPES}}}},
        "example": {"identifiers": {"email": "person@example.com", "username": "example"}},
    }}}},
)
async def create_search(request: Request):
    """Queue an in-memory scan. Stream or poll the returned id; no terminal input or report file is used."""
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
        return error("Content-Type must be application/json.", 415)
    body = await request.body()
    if len(body) > 16384:
        return error("Request is too large.", 413)
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return error("Malformed JSON.")
    identifiers, fields = validate_identifiers(payload)
    if fields:
        return error("Check the supplied identifiers.", fields=fields)
    purge_expired()
    if sum(job["status"] in {"queued", "running"} for job in jobs.values()) >= 8:
        return error("The scan queue is full. Try again shortly.", 429)
    # Keep a bounded number of completed jobs even under sustained local use.
    while len(jobs) >= 64:
        completed = [key for key, job in jobs.items() if job["status"] in {"completed", "failed"}]
        if not completed:
            break
        del jobs[completed[0]]
    job_id = uuid.uuid4().hex
    job = {"id": job_id, "status": "queued", "message": "Search queued.", "result": None, "error": None, "updated": time.monotonic(), "_revision": 0, "progress": None}
    jobs[job_id] = job
    task = asyncio.create_task(execute_scan(job_id, identifiers))
    tasks.add(task)
    task.add_done_callback(tasks.discard)
    return JSONResponse({"id": job_id, "status": "queued", "message": job["message"]}, status_code=202)


@app.get("/api/search/{job_id}", response_model=SearchJob, responses={404: {"model": ApiError}})
async def get_search(job_id: str):
    """Read a job until completed or failed. Completed jobs expire after one hour."""
    purge_expired()
    if job_id not in jobs:
        return error("Search not found or expired. Submit a new search.", 404)
    return public_job(jobs[job_id])


@app.get(
    "/api/search/{job_id}/events",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {"schema": {"type": "string"}}},
                     "description": "SSE data messages containing SearchJob snapshots, including partial results. Closes after a terminal status."},
               404: {"model": ApiError}},
)
async def search_events(job_id: str):
    """Stream current state immediately, then partial results as sources finish.

    Reconnecting receives the latest complete snapshot; disconnecting does not
    cancel the scan. The polling endpoint remains available as a fallback.
    """
    purge_expired()
    if job_id not in jobs:
        return error("Search not found or expired. Submit a new search.", 404)
    job = jobs[job_id]

    async def events():
        revision = -1
        heartbeat = time.monotonic()
        while True:
            if job.get("_revision", 0) != revision:
                revision = job.get("_revision", 0)
                yield "data: " + json.dumps(public_job(job)) + "\n\n"
                heartbeat = time.monotonic()
                if job["status"] in {"completed", "failed"}:
                    return
            elif time.monotonic() - heartbeat >= 10:
                yield ": heartbeat\n\n"
                heartbeat = time.monotonic()
            await asyncio.sleep(0.2)

    return StreamingResponse(events(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no",
    })
