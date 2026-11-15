"""Regression coverage for catalog templates and search-engine query echoes."""
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlparse

from SecurityApp import Backend as scanner


class CatalogTests(unittest.TestCase):
    def test_amazon_template_keeps_site_restriction_and_encodes_query(self):
        tool = scanner.Tool('Amazon Usernames (M)', 'https://www.google.com/search?q=site:amazon.com+%3Cusername%3E', 'Username', 'Username')
        query = 'sample+tag@example.com & other'
        url = scanner.build_search_url(tool, query)
        self.assertEqual(urlparse(url).hostname, 'www.google.com')
        self.assertEqual(parse_qs(urlparse(url).query), {'q': [f'site:amazon.com {query}']})

    def test_category_excludes_catalog_root(self):
        tree = {'name': 'OSINT Framework', 'type': 'folder', 'children': [
            {'name': 'Username', 'type': 'folder', 'children': [
                {'name': 'Example', 'type': 'url', 'url': 'https://example.com'}]}]}
        self.assertEqual(scanner.flatten_tree(tree)[0].parent_category, 'Username')


class PageTests(unittest.IsolatedAsyncioTestCase):
    async def test_google_echo_is_manual_review_with_zero_matches(self):
        page = Mock()
        page.goto = AsyncMock(return_value=Mock(status=200))
        page.wait_for_timeout = AsyncMock()
        page.evaluate = AsyncMock(side_effect=AssertionError('Do not count a search page'))
        page.url = 'https://www.google.com/search?q=site%3Aamazon.com+sample_user'
        tool = scanner.Tool('Amazon Usernames (M)', 'https://www.google.com/search?q=site:amazon.com+%3Cusername%3E', 'Username', 'Username')
        with patch.dict('os.environ', {'OSINT_PAGE_WAIT_MS': '0'}):
            result = await scanner.analyze_page(page, tool, 'sample_user', scanner.InputType.USERNAME)
        self.assertEqual(result.status, 'manual_review')
        self.assertEqual(result.match_count, 0)
        self.assertEqual(result.final_url, page.url)
        self.assertEqual(result.source_url, tool.url)
        page.evaluate.assert_not_called()

    async def test_redirect_to_search_engine_is_also_manual_review(self):
        page = Mock()
        page.goto = AsyncMock(return_value=Mock(status=200))
        page.wait_for_timeout = AsyncMock()
        page.url = 'https://www.bing.com/search?q=sample_user'
        result = await scanner.analyze_page(page, scanner.Tool('Directory', 'https://example.com', 'Username', 'Username'), 'sample_user', scanner.InputType.USERNAME)
        self.assertEqual(result.status, 'manual_review')
        self.assertEqual(result.match_count, 0)

class SchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def test_streams_fast_results_before_slow_source_with_bounded_concurrency(self):
        import asyncio
        active = 0
        peak = 0
        completed = []
        first = asyncio.Event()
        release = asyncio.Event()
        context = Mock()
        context.new_page = AsyncMock(side_effect=lambda: Mock(close=AsyncMock()))

        async def analyze(page, tool, query, input_type):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                if tool.name == 'slow':
                    await release.wait()
                return scanner.ToolResult(query, input_type.value, tool.name, 'Username', tool.url, 'no_match')
            finally:
                active -= 1

        def on_result(result):
            completed.append(result.tool_name)
            first.set()

        tools = [scanner.Tool(name, 'https://example.com', 'Username', 'Username') for name in ('slow', 'fast1', 'fast2', 'fast3')]
        with patch.object(scanner, 'analyze_page', side_effect=analyze):
            task = asyncio.create_task(scanner.search_one_query('sample', scanner.InputType.USERNAME, tools, context, asyncio.Semaphore(2), 0, on_result))
            await asyncio.wait_for(first.wait(), timeout=1)
            self.assertFalse(task.done())
            self.assertNotIn('slow', completed)
            release.set()
            results = await task
        self.assertEqual(len(results), 4)
        self.assertLessEqual(peak, 2)

    async def test_slow_source_times_out_without_losing_fast_results(self):
        import asyncio
        context = Mock()
        context.new_page = AsyncMock(side_effect=lambda: Mock(close=AsyncMock()))

        async def analyze(page, tool, query, input_type):
            if tool.name == 'slow':
                await asyncio.sleep(10)
            return scanner.ToolResult(query, input_type.value, tool.name, 'Username', tool.url, 'success', 1)

        tools = [scanner.Tool(name, 'https://example.com', 'Username', 'Username') for name in ('slow', 'fast')]
        with patch.object(scanner, 'analyze_page', side_effect=analyze):
            results = await scanner.search_one_query('sample', scanner.InputType.USERNAME, tools, context, asyncio.Semaphore(2), 0, source_timeout=.01)
        self.assertEqual({r.tool_name: r.status for r in results}, {'slow': 'error', 'fast': 'success'})

class SourceFilteringTests(unittest.TestCase):
    def test_repository_links_are_not_scanned_but_profile_searches_remain(self):
        urls = ['https://github.com/example/tool', 'https://github.com/example/tool/wiki',
                'https://raw.githubusercontent.com/example/tool/main/tool.py',
                'https://example.github.io/docs/', 'https://github.com/search?type=users',
                'https://example.com/search']
        tools = [scanner.Tool(str(i), url, 'Username', 'Username') for i, url in enumerate(urls)]
        selected = scanner.get_relevant_tools(tools, scanner.InputType.USERNAME)
        self.assertEqual([tool.url for tool in selected], urls[-2:])
