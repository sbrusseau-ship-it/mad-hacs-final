"""Contract tests isolate external services; Docker E2E exercises Chromium."""
import asyncio
import os
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient
from SecurityApp import api
from SecurityApp.Backend import InputType, Tool, ToolResult


class ApiTests(unittest.TestCase):
    def setUp(self):
        async def no_sherlock(username, on_plan, on_result):
            on_plan(0)
        self.sherlock_patch = patch.object(api, 'run_sherlock', side_effect=no_sherlock)
        self.sherlock_mock = self.sherlock_patch.start()
        self.addCleanup(self.sherlock_patch.stop)
        api.jobs.clear()
        self.client_context = TestClient(api.app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)

    def wait_job(self, job_id):
        for _ in range(100):
            job = self.client.get(f"/api/search/{job_id}").json()
            if job["status"] in {"completed", "failed"}:
                return job
            time.sleep(0.01)
        self.fail("Job did not terminate")

    def test_validation_and_unknown_job(self):
        for payload in ({}, {"identifiers": {}}, {"identifiers": {"ip": "999.1.1.1"}}, {"identifiers": {"email": 42}}, {"identifiers": {"unsupported": "value"}}, {"identifiers": {"name": "   "}}):
            response = self.client.post("/api/search", json=payload)
            self.assertEqual(response.status_code, 400)
            self.assertIsInstance(response.json()["error"], str)
            self.assertIn("fields", response.json())
        self.assertEqual(self.client.get("/api/search/missing").status_code, 404)
        self.assertEqual(self.client.post("/api/search", content="{").status_code, 415)
        self.assertEqual(self.client.post("/api/search", content="{", headers={"Content-Type": "application/json"}).status_code, 400)
        self.assertEqual(self.client.get("/api/health").json(), {"status": "ok"})

    def test_real_contract_passes_typed_inputs_to_scanner(self):
        seen = []

        async def scan(queries, tools, **kwargs):
            seen.extend(queries)
            self.assertIsNone(kwargs["max_tools_per_query"])
            result = ToolResult("123456789", "ssn", "Fixture", "Public Records", "https://example.com", "success", 2, ["Text matches: 2"])
            return {"summary": {"total_tools_searched": 1, "tools_with_matches": 1, "total_matches": 2}, "all_results": [result], "2d_array": [["123456789", "Fixture"]]}

        with patch.object(api.scanner, "fetch_osint_tree", return_value={}), patch.object(api.scanner, "flatten_tree", return_value=[Tool("Fixture", "https://example.com", "Public Records", "Public Records")]), patch.object(api.scanner, "run_parallel_osint_search", side_effect=scan), patch("builtins.input", side_effect=AssertionError("HTTP API must not prompt")):
            response = self.client.post("/api/search", json={"identifiers": {"ssn": "123456789", "name": "李", "address": "123 Main St", "ip": "2001:db8::1"}})
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.json()["status"], "queued")
            job = self.wait_job(response.json()["id"])
        self.assertEqual(job["status"], "completed")
        self.assertIsNone(job["error"])
        self.assertIsNone(job["result"]["summary"]["tool_limit_per_query"])
        self.assertEqual(job["result"]["results"][0]["match_count"], 2)
        self.assertEqual(job["result"]["matches"], [["123456789", "Fixture"]])
        stream = self.client.get(f"/api/search/{job['id']}/events")
        self.assertEqual(stream.status_code, 200)
        import json
        snapshot = json.loads(stream.text.split("data: ", 1)[1])
        self.assertEqual(snapshot["status"], "completed")
        self.assertNotIn("_revision", snapshot)
        self.assertEqual(snapshot["result"], job["result"])
        self.assertIn(("123456789", InputType.SSN), seen)
        self.assertIn(("李", InputType.NAME), seen)
        self.assertIn(("123 Main St", InputType.ADDRESS), seen)

    def test_failure_is_pollable_and_does_not_leak_exception(self):
        with patch.object(api.scanner, "fetch_osint_tree", side_effect=RuntimeError("secret@example.com")):
            response = self.client.post("/api/search", json={"identifiers": {"email": "secret@example.com"}})
            job = self.wait_job(response.json()["id"])
        self.assertEqual(job["status"], "failed")
        self.assertNotIn("secret@example.com", job["error"])
        self.assertIsNone(job["result"])

    def test_timeout(self):
        async def stalled(*args, **kwargs):
            await asyncio.sleep(10)

        with patch.object(api.scanner, "fetch_osint_tree", return_value={}), patch.object(api.scanner, "flatten_tree", return_value=[object()]), patch.object(api.scanner, "run_parallel_osint_search", side_effect=stalled), patch.dict(os.environ, {"OSINT_SCAN_TIMEOUT": "0.01"}):
            response = self.client.post("/api/search", json={"identifiers": {"username": "example"}})
            job = self.wait_job(response.json()["id"])
        self.assertEqual(job["status"], "failed")
        self.assertIn("time limit", job["error"])

    def test_queue_limit(self):
        for index in range(8):
            api.jobs[str(index)] = {"status": "running", "updated": time.monotonic()}
        response = self.client.post("/api/search", json={"identifiers": {"username": "example"}})
        self.assertEqual(response.status_code, 429)

    def test_openapi_documents_request_and_poll_response(self):
        schema = self.client.get("/openapi.json").json()
        request = schema["paths"]["/api/search"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(set(request["properties"]["identifiers"]["properties"]), set(api.FIELD_TYPES))
        response = schema["paths"]["/api/search/{job_id}"]["get"]["responses"]["200"]
        self.assertEqual(response["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/SearchJob")

    def test_shutdown_cancels_running_jobs(self):
        cancelled = []

        async def stalled(*args, **kwargs):
            try:
                await asyncio.sleep(10)
            finally:
                cancelled.append(True)

        with patch.object(api.scanner, "fetch_osint_tree", return_value={}), patch.object(api.scanner, "flatten_tree", return_value=[object()]), patch.object(api.scanner, "run_parallel_osint_search", side_effect=stalled):
            self.client.post("/api/search", json={"identifiers": {"username": "example"}})
            time.sleep(0.02)
            self.client_context.__exit__(None, None, None)
        self.assertEqual(cancelled, [True])
        self.assertFalse(api.tasks)
        self.assertFalse(api.jobs)
        # tearDown still owns an open context.
        self.client_context = TestClient(api.app)
        self.client = self.client_context.__enter__()

    def test_username_uses_sherlock_and_email_does_not(self):
        async def sherlock(username, on_plan, on_result):
            on_plan(1)
            on_result(ToolResult(username, 'username', 'Sherlock · Fixture', 'Username', 'https://example.com/u/sample', 'success', 1, backend='sherlock'))

        async def browser(queries, tools, **kwargs):
            kwargs['on_plan'](1)
            row = ToolResult(queries[0][0], queries[0][1].value, 'Browser fixture', 'Username', 'https://example.com', 'no_match')
            kwargs['on_result'](row)
            return api.scanner.summarize_results(queries, [row], 1)

        self.sherlock_mock.side_effect = sherlock
        with patch.object(api.scanner, 'fetch_osint_tree', return_value={}), patch.object(api.scanner, 'flatten_tree', return_value=[object()]), patch.object(api.scanner, 'run_parallel_osint_search', side_effect=browser):
            accepted = self.client.post('/api/search', json={'identifiers': {'username': 'sample'}}).json()
            job = self.wait_job(accepted['id'])
            self.assertEqual(job['status'], 'completed')
            self.assertEqual(job['progress'], {'completed_sources': 2, 'total_sources': 2})
            self.assertEqual({r['backend'] for r in job['result']['results']}, {'browser', 'sherlock'})
            self.assertEqual(job['result']['summary']['tools_with_matches'], 1)
            self.sherlock_mock.assert_awaited_once()
            self.sherlock_mock.reset_mock()
            accepted = self.client.post('/api/search', json={'identifiers': {'email': 'sample@example.com'}}).json()
            job = self.wait_job(accepted['id'])
            self.assertEqual(job['status'], 'completed')
            self.sherlock_mock.assert_not_awaited()

    def test_sherlock_failure_preserves_browser_results(self):
        self.sherlock_mock.side_effect = RuntimeError('upstream failure')

        async def browser(queries, tools, **kwargs):
            kwargs['on_plan'](1)
            row = ToolResult('sample', 'username', 'Browser fixture', 'Username', 'https://example.com', 'success', 1)
            kwargs['on_result'](row)
            return api.scanner.summarize_results(queries, [row], 1)

        with patch.object(api.scanner, 'fetch_osint_tree', return_value={}), patch.object(api.scanner, 'flatten_tree', return_value=[object()]), patch.object(api.scanner, 'run_parallel_osint_search', side_effect=browser):
            accepted = self.client.post('/api/search', json={'identifiers': {'username': 'sample'}}).json()
            job = self.wait_job(accepted['id'])
        self.assertEqual(job['status'], 'completed')
        self.assertEqual(job['result']['summary']['tools_with_matches'], 1)
        self.assertEqual(job['progress'], {'completed_sources': 2, 'total_sources': 2})
        self.assertEqual(job['result']['results'][-1]['backend'], 'sherlock')
        self.assertEqual(job['result']['results'][-1]['status'], 'error')

    def test_scanner_closes_browser_when_cancelled(self):
        async def verify():
            context = AsyncMock()
            browser = AsyncMock()
            browser.new_context.return_value = context
            playwright = MagicMock()
            playwright.chromium.launch = AsyncMock(return_value=browser)
            manager = AsyncMock()
            manager.__aenter__.return_value = playwright

            async def stalled(*args, **kwargs):
                await asyncio.sleep(10)

            with patch.object(api.scanner, "async_playwright", return_value=manager), patch.object(api.scanner, "search_one_query", side_effect=stalled):
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(api.scanner.run_parallel_osint_search([("example", InputType.USERNAME)], []), timeout=0.01)
            browser.close.assert_awaited_once()

        asyncio.run(verify())


if __name__ == "__main__":
    unittest.main()
