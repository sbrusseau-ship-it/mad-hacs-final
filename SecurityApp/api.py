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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import Backend as scanner


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
    source_url: str | None = None
    final_url: str | None = None


class SearchResult(BaseModel):
    summary: dict = Field(description="Counts, queried values/types, timestamp, status breakdown, and tool_limit_per_query.")
    results: list[ToolResultResponse]
    matches: list[tuple[str, str]] = Field(description="Pairs of input value and tool name for tools with page occurrences.")


class SearchJob(BaseModel):
    id: str
    status: Literal["queued", "running", "completed", "failed"]
    message: str
    result: SearchResult | None
    error: str | None


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
    return {key: value for key, value in job.items() if key != "updated"}


async def execute_scan(job_id, identifiers):
    job = jobs[job_id]
    try:
        async with scan_lock:
            job.update(status="running", message="Searching public sources.")
            queries = [(value, FIELD_TYPES[key]) for key, value in identifiers.items()]

            tool_limit = int(os.environ.get("OSINT_MAX_TOOLS", "0")) or None
            scan_timeout = float(os.environ.get("OSINT_SCAN_TIMEOUT", "0")) or None

            async def run():
                tree = await asyncio.to_thread(scanner.fetch_osint_tree)
                tools = scanner.flatten_tree(tree)
                if not tools:
                    raise ValueError("No tools in the configured OSINT tree")
                return await scanner.run_parallel_osint_search(
                    queries, tools, headless=True,
                    max_concurrent=int(os.environ.get("OSINT_CONCURRENCY", "3")),
                    delay_between=float(os.environ.get("OSINT_DELAY", "0.2")),
                    max_tools_per_query=tool_limit,
                )

            data = await asyncio.wait_for(run(), timeout=scan_timeout)
            data["summary"]["tool_limit_per_query"] = tool_limit
            job.update(status="completed", message="Search completed. Matches are unverified page occurrences, not confirmed breaches.", result={
                "summary": data["summary"],
                "results": [asdict(result) for result in data["all_results"]],
                "matches": data["2d_array"],
            })
    except asyncio.TimeoutError:
        job.update(status="failed", message="Search timed out.", error="The scan exceeded its time limit. Try fewer identifiers.")
    except asyncio.CancelledError:
        raise
    except Exception:
        # Do not echo upstream exceptions, which may contain personal identifiers.
        job.update(status="failed", message="Search failed.", error="The scanner could not complete the search. Check backend connectivity and browser installation.")
    finally:
        job["updated"] = time.monotonic()


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
    """Queue an in-memory scan. Poll the returned id; no terminal input or report file is used."""
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
    job = {"id": job_id, "status": "queued", "message": "Search queued.", "result": None, "error": None, "updated": time.monotonic()}
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
