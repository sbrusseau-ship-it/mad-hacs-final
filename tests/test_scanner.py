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
