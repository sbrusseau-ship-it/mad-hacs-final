# osint_full_framework.py
# pip install playwright requests
# playwright install chromium

import asyncio
import json
import re
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, quote
from collections import defaultdict

import requests
from playwright.async_api import async_playwright, Page, BrowserContext

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("osint_full")


# ═══════════════════════════════════════════════════════
# 1. FETCH THE FULL OSINT FRAMEWORK TREE FROM GITHUB
# ═══════════════════════════════════════════════════════
OSINT_JSON_URL = "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json"


def fetch_osint_tree() -> dict:
    """Download the live OSINT Framework tree."""
    log.info("Fetching OSINT Framework tree from GitHub...")
    resp = requests.get(OSINT_JSON_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    log.info(f"Loaded tree: root='{data['name']}', {len(data.get('children', []))} top-level categories")
    return data


# ═══════════════════════════════════════════════════════
# 2. PARSE TREE → FLAT LIST OF TOOLS WITH CATEGORIES
# ═══════════════════════════════════════════════════════
@dataclass
class Tool:
    name: str
    url: str
    category_path: str  # e.g. "Username > Username Search Engines"
    parent_category: str  # top-level category


def flatten_tree(node: dict, path: str = "", tools: list = None) -> list:
    """Recursively walk the tree and extract all URL-type nodes."""
    if tools is None:
        tools = []

    node_name = node.get("name", "Unknown")
    node_type = node.get("type", "folder")
    node_url = node.get("url", "")

    current_path = f"{path} > {node_name}" if path else node_name

    if node_type == "url" and node_url:
        # Determine top-level category (first segment of path)
        top_cat = path.split(" > ")[0] if " > " in path else node_name
        tools.append(Tool(
            name=node_name,
            url=node_url,
            category_path=current_path,
            parent_category=top_cat
        ))
    elif node_type == "folder" and "children" in node:
        for child in node["children"]:
            flatten_tree(child, current_path, tools)

    return tools


# ═══════════════════════════════════════════════════════
# 3. INPUT TYPE DETECTION
# ═══════════════════════════════════════════════════════
class InputType(Enum):
    PHONE_US = "phone_us"
    PHONE_INTL = "phone_intl"
    EMAIL = "email"
    SSN = "ssn"
    USERNAME = "username"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    NAME = "name"
    URL_LINK = "url_link"
    HASH = "hash"
    BITCOIN_ADDR = "bitcoin_address"
    UNKNOWN = "unknown"


def detect_input_type(value: str) -> InputType:
    v = value.strip()

    if re.match(r"^\d{3}-\d{2}-\d{4}$", v):
        return InputType.SSN
    if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", v):
        return InputType.EMAIL
    if re.match(r"^[\(]?\d{3}[\)]?[-.\s]?\d{3}[-.\s]?\d{4}$", v):
        return InputType.PHONE_US
    if re.match(r"^\+?\d{7,15}$", v.replace(" ", "").replace("-", "")):
        return InputType.PHONE_INTL
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
        return InputType.IP_ADDRESS
    if re.match(r"^[a-fA-F0-9]{32}$", v) or re.match(r"^[a-fA-F0-9]{40}$", v) or re.match(r"^[a-fA-F0-9]{64}$", v):
        return InputType.HASH
    if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", v) or v.startswith("bc1"):
        return InputType.BITCOIN_ADDR
    if re.match(r"^https?://", v):
        return InputType.URL_LINK
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v) and "." in v and "@" not in v:
        return InputType.DOMAIN
    if re.match(r"^[a-zA-Z0-9_.]{3,30}$", v) and " " not in v:
        return InputType.USERNAME
    if re.match(r"^[A-Za-z]+(?:\s+[A-Za-z]+)+$", v):
        return InputType.NAME

    return InputType.UNKNOWN


# ═══════════════════════════════════════════════════════
# 4. MAP INPUT TYPE → RELEVANT OSINT CATEGORIES
# ═══════════════════════════════════════════════════════
CATEGORY_MAP = {
    InputType.PHONE_US: [
        "Telephone Numbers", "Public Records", "People Search Engines",
        "Social Networks", "Dating", "Compliance & Risk Intelligence"
    ],
    InputType.PHONE_INTL: [
        "Telephone Numbers", "Public Records", "People Search Engines",
        "Social Networks", "Compliance & Risk Intelligence"
    ],
    InputType.EMAIL: [
        "Email Address", "Social Networks", "Username",
        "Breach Data", "People Search Engines", "Domain Name"
    ],
    InputType.USERNAME: [
        "Username", "Social Networks", "Online Communities",
        "Gaming", "Dating", "People Search Engines"
    ],
    InputType.DOMAIN: [
        "Domain Name", "Cloud Infrastructure", "IP & MAC Address",
        "Search Engines", "Archives"
    ],
    InputType.IP_ADDRESS: [
        "IP & MAC Address", "Geolocation Tools / Maps",
        "Cloud Infrastructure", "Search Engines"
    ],
    InputType.NAME: [
        "People Search Engines", "Public Records", "Social Networks",
        "Dating", "Business Records", "Compliance & Risk Intelligence"
    ],
    InputType.SSN: [
        "Public Records", "Compliance & Risk Intelligence",
        "People Search Engines"
    ],
    InputType.URL_LINK: [
        "Search Engines", "Archives", "Social Networks",
        "Disinformation & Media Verification"
    ],
    InputType.HASH: [
        "Encoding / Decoding", "Search Engines", "Blockchain & Cryptocurrency"
    ],
    InputType.BITCOIN_ADDR: [
        "Blockchain & Cryptocurrency", "Search Engines"
    ],
    InputType.UNKNOWN: [],  # will search everything
}


def get_relevant_tools(all_tools: list, input_type: InputType) -> list:
    """Filter tools by categories relevant to the input type."""
    categories = CATEGORY_MAP.get(input_type, [])

    if not categories:
        # UNKNOWN type → return ALL tools
        log.warning("Unknown input type — will search ALL tools in the framework")
        return all_tools

    relevant = []
    for tool in all_tools:
        # Check if tool's category path matches any relevant category
        for cat in categories:
            if cat.lower() in tool.category_path.lower() or cat.lower() in tool.parent_category.lower():
                relevant.append(tool)
                break

    log.info(f"Input type '{input_type.value}' → {len(relevant)} tools across categories: {categories}")
    return relevant


# ═══════════════════════════════════════════════════════
# 5. SEARCH URL CONSTRUCTION
# ═══════════════════════════════════════════════════════
def build_search_url(tool: Tool, query: str) -> str:
    """
    Try to construct a search URL for the tool.
    Falls back to the tool's base URL if no search pattern is known.
    """
    url = tool.url.rstrip("/")
    domain = urlparse(url).netloc
    q = quote(query)

    # Common search URL patterns by domain
    patterns = {
        # Username
        "namechk.com": f"https://namechk.com/en/search?q={q}",
        "knowem.com": f"https://knowem.com/search/{q}",
        "usersearch.org": f"https://usersearch.org/results.php?username={q}",
        "whatsmyname.app": f"https://whatsmyname.app/?q={q}",
        "sherlock-project.github.io": f"https://sherlock-project.github.io/{q}",

        # Email
        "haveibeenpwned.com": f"https://haveibeenpwned.com/unifiedsearch/{q}",
        "hunter.io": f"https://hunter.io/email-finder/{q}",
        "emailrep.io": f"https://emailrep.io/{q}",
        "gravatar.com": f"https://en.gravatar.com/{q}",
        "holehe.osint.fr": f"https://holehe.osint.fr/{q}",

        # Phone
        "truecaller.com": f"https://www.truecaller.com/search/us/{q}",
        "spydialer.com": f"https://www.spydialer.com/default.aspx?s=phone&v={q}",
        "whitepages.com": f"https://www.whitepages.com/phone/{q}",
        "numsy.com": f"https://www.numsy.com/{q}",
        "phonevalidator.com": f"https://www.phonevalidator.com/index.aspx?phone={q}",
        "opencnam.com": f"https://www.opencnam.com/phone/{q}",
        "hlrlookup.com": f"https://www.hlrlookup.com/hlr-lookup/?msisdn={q}",
        "familytreenow.com": f"https://www.familytreenow.com/search/genealogy/results?first=&last=&phone={q}",
        "mrnumber.com": f"https://mrnumber.com/website/lookup?phone={q}",
        "nextcaller.com": f"https://www.nextcaller.com/lookup/{q}",
        "data24-7.com": f"https://www.data24-7.com/search?query={q}",
        "hiya.com": f"https://www.hiya.com/lookup/{q}",
        "fonefinder.net": f"https://www.fonefinder.net/findome.php?npa={q}",
        "whocald.com": f"https://whocald.com/phone/{q}",

        # Domain
        "domaintools.com": f"https://whois.domaintools.com/{q}",
        "dnslytics.com": f"https://dnslytics.com/domain/{q}",
        "viewdns.info": f"https://viewdns.info/whois/?domain={q}",
        "securitytrails.com": f"https://securitytrails.com/domain/{q}",
        "whois.com": f"https://www.whois.com/whois/{q}",

        # IP
        "ipinfo.io": f"https://ipinfo.io/{q}",
        "abuseipdb.com": f"https://www.abuseipdb.com/check/{q}",
        "virustotal.com": f"https://www.virustotal.com/gui/ip-address/{q}",
        "shodan.io": f"https://www.shodan.io/host/{q}",
        "censys.io": f"https://search.censys.io/hosts/{q}",

        # People / Name
        "truepeoplesearch.com": f"https://www.truepeoplesearch.com/results?name={q}",
        "fastpeoplesearch.com": f"https://www.fastpeoplesearch.com/search?q={q}",
        "cubib.com": f"https://cubib.com/search?name={q}",
        "thatsthem.com": f"https://thatsthem.com/name/{q.replace(' ', '-')}",
        "spokeo.com": f"https://www.spokeo.com/name/{q.replace(' ', '-')}",

        # SSN
        "ssnvalidator.com": f"https://www.ssnvalidator.com/ssn/{q}",
        "ssncheck.com": f"https://www.ssncheck.com/{q}",

        # Bitcoin
        "blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{q}",
        "blockchair.com": f"https://blockchair.com/bitcoin/address/{q}",
        "mempool.space": f"https://mempool.space/address/{q}",

        # Hash
        "md5decrypt.net": f"https://www.md5decrypt.net/en/Sha256/#input={q}",
        "crackstation.net": f"https://crackstation.net/?c={q}",

        # General search fallbacks
        "google.com": f"https://www.google.com/search?q={q}",
        "bing.com": f"https://www.bing.com/search?q={q}",
        "duckduckgo.com": f"https://duckduckgo.com/?q={q}",
        "yandex.com": f"https://yandex.com/search/?text={q}",
        "waybackmachine.org": f"https://web.archive.org/web/*/{q}",
        "archive.org": f"https://web.archive.org/web/*/{q}",
    }

    # Try exact domain match
    for pattern_domain, pattern_url in patterns.items():
        if pattern_domain in domain:
            return pattern_url

    # Try to detect search pattern from URL structure
    if "/search" in url or "/lookup" in url or "/find" in url:
        return f"{url}?q={q}" if "?" not in url else f"{url}&q={q}"

    # Fallback: just visit the base URL
    return url


# ═══════════════════════════════════════════════════════
# 6. PAGE ANALYSIS & MATCH COUNTING
# ═══════════════════════════════════════════════════════
@dataclass
class ToolResult:
    tool_name: str
    category: str
    url_searched: str
    status: str
    match_count: int = 0
    match_details: list = field(default_factory=list)
    error: Optional[str] = None
    page_title: str = ""


async def analyze_page(page: Page, tool: Tool, query: str) -> ToolResult:
    """Visit a tool's search URL and count all possible matches."""
    search_url = build_search_url(tool, query)

    try:
        log.info(f"  → {tool.name}: {search_url[:80]}...")
        response = await page.goto(search_url, wait_until="domcontentloaded", timeout=20000)

        if response and response.status >= 400:
            return ToolResult(
                tool_name=tool.name, category=tool.parent_category,
                url_searched=search_url, status="blocked",
                error=f"HTTP {response.status}"
            )

        # Wait for dynamic content
        await page.wait_for_timeout(3000)

        page_title = await page.title()
        match_count = 0
        match_details = []

        # ── Strategy 1: Full body text search ──
        try:
            body_text = await page.evaluate("() => document.body.innerText")
            text_occurrences = len(re.findall(re.escape(query), body_text, re.IGNORECASE))
            if text_occurrences > 0:
                match_count += text_occurrences
                match_details.append(f"Text matches: {text_occurrences}")
        except Exception:
            pass

        # ── Strategy 2: HTML source search ──
        try:
            html = await page.evaluate("() => document.documentElement.outerHTML")
            html_occurrences = len(re.findall(re.escape(query), html, re.IGNORECASE))
            if html_occurrences > 0:
                match_count += html_occurrences
                match_details.append(f"HTML matches: {html_occurrences}")
        except Exception:
            pass

        # ── Strategy 3: All links on page ──
        try:
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a')).map(a => ({
                    href: a.href, text: a.innerText
                }))
            """)
            query_clean = query.replace(" ", "").replace("-", "").replace(".", "").lower()
            matching_links = []
            for link in links:
                link_clean = link.get("href", "").replace(" ", "").replace("-", "").replace(".", "").lower()
                text_clean = link.get("text", "").replace(" ", "").replace("-", "").replace(".", "").lower()
                if query_clean in link_clean or query_clean in text_clean:
                    matching_links.append(link)
            if matching_links:
                match_count += len(matching_links)
                match_details.append(f"Matching links: {len(matching_links)}")
        except Exception:
            pass

        # ── Strategy 4: Common result container selectors ──
        result_selectors = [
            ".result", ".results", ".search-result", ".search-results",
            ".card", ".cards", ".profile", ".profiles",
            ".item", ".items", ".entry", ".entries",
            ".record", ".records", ".listing", ".listings",
            ".match", ".matches", ".found",
            "table tr", ".row", ".data-row",
            ".info", ".info-card", ".detail",
            "[class*='result']", "[class*='match']", "[class*='found']",
            "[class*='profile']", "[class*='record']",
        ]
        for selector in result_selectors:
            try:
                elements = await page.query_selector_all(selector)
                if elements and len(elements) > 0:
                    # Check if any contain the query
                    has_match = False
                    for el in elements[:50]:  # Limit check
                        text = await el.inner_text()
                        if query.lower() in text.lower():
                            has_match = True
                            break
                    if has_match:
                        match_count += len(elements)
                        match_details.append(f"Selector '{selector}': {len(elements)} elements with match")
                        break  # Don't double-count similar selectors
            except Exception:
                pass

        # ── Strategy 5: Meta tags and title ──
        try:
            meta_desc = await page.evaluate("""
                () => document.querySelector('meta[name="description"]')?.content || ''
            """)
            if query.lower() in meta_desc.lower():
                match_count += 1
                match_details.append("Match in meta description")
        except Exception:
            pass

        status = "success" if match_count > 0 else "no_match"

        return ToolResult(
            tool_name=tool.name, category=tool.parent_category,
            url_searched=search_url, status=status,
            match_count=match_count, match_details=match_details,
            page_title=page_title
        )

    except Exception as e:
        return ToolResult(
            tool_name=tool.name, category=tool.parent_category,
            url_searched=search_url, status="error",
            error=str(e)[:200]
        )


# ═══════════════════════════════════════════════════════
# 7. DEEP CRAWL — follow every link on pages with matches
# ═══════════════════════════════════════════════════════
async def deep_crawl(page: Page, start_url: str, query: str, max_depth: int = 2, max_pages: int = 30) -> list:
    """BFS crawl following all links, counting matches at each page."""
    results = []
    visited = set()
    queue = [(start_url, 0)]
    base_domain = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        # Same-domain only
        if urlparse(url).netloc != base_domain:
            continue

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(1500)

            body_text = await page.evaluate("() => document.body.innerText")
            occurrences = len(re.findall(re.escape(query), body_text, re.IGNORECASE))

            if occurrences > 0:
                results.append({"url": url, "depth": depth, "matches": occurrences})

            if depth < max_depth:
                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a'))
                        .map(a => a.href)
                        .filter(h => h && h.startsWith('http'))
                """)
                for link in links[:15]:
                    if link not in visited:
                        queue.append((link, depth + 1))

        except Exception:
            continue

    return results


# ═══════════════════════════════════════════════════════
# 8. MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════
@dataclass
class FullOSINTReport:
    input_value: str
    input_type: InputType
    total_tools_searched: int = 0
    tools_with_matches: int = 0
    total_matches: int = 0
    results: list = field(default_factory=list)
    deep_crawl_results: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


async def run_full_osint_search(
    query: str,
    deep_crawl: bool = False,
    headless: bool = True,
    max_tools: int = None,
    delay_between: float = 1.5
) -> FullOSINTReport:
    """
    Full pipeline:
    1. Fetch OSINT Framework tree
    2. Detect input type
    3. Filter relevant tools
    4. Search each with Playwright
    5. Optionally deep-crawl
    6. Return comprehensive report
    """
    # Step 1: Get the tree
    tree = fetch_osint_tree()
    all_tools = flatten_tree(tree)
    log.info(f"Total tools in OSINT Framework: {len(all_tools)}")

    # Step 2: Detect type
    input_type = detect_input_type(query)
    log.info(f"Detected input type: {input_type.value} for '{query}'")

    # Step 3: Get relevant tools
    relevant_tools = get_relevant_tools(all_tools, input_type)
    if max_tools:
        relevant_tools = relevant_tools[:max_tools]
    log.info(f"Will search {len(relevant_tools)} tools")

    report = FullOSINTReport(input_value=query, input_type=input_type)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-extensions",
            ]
        )

        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )

        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            window.chrome = { runtime: {} };
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        """)

        page = await context.new_page()

        # ── Phase 1: Search all tools ──
        log.info(f"\n{'='*70}")
        log.info(f"PHASE 1: Searching {len(relevant_tools)} OSINT tools")
        log.info(f"{'='*70}")

        for i, tool in enumerate(relevant_tools, 1):
            log.info(f"[{i}/{len(relevant_tools)}] {tool.name} ({tool.parent_category})")
            result = await analyze_page(page, tool, query)
            report.results.append(result)
            report.total_matches += result.match_count
            if result.match_count > 0:
                report.tools_with_matches += 1
                log.info(f"    ✅ {result.match_count} matches — {result.match_details[:3]}")
            else:
                log.info(f"    ❌ {result.status}" + (f" — {result.error}" if result.error else ""))

            report.total_tools_searched += 1

            # Rate limiting
            if i < len(relevant_tools):
                await asyncio.sleep(delay_between)

        # ── Phase 2: Deep crawl ──
        if deep_crawl:
            log.info(f"\n{'='*70}")
            log.info(f"PHASE 2: Deep crawling pages with matches")
            log.info(f"{'='*70}")

            for result in report.results:
                if result.match_count > 0 and result.status == "success":
                    log.info(f"  Deep crawling: {result.tool_name}")
                    crawl_results = await deep_crawl(page, result.url_searched, query, max_depth=2, max_pages=20)
                    report.deep_crawl_results.extend(crawl_results)
                    for cr in crawl_results:
                        log.info(f"    [Depth {cr['depth']}] {cr['url'][:70]} — {cr['matches']} matches")
                    await asyncio.sleep(1)

        await browser.close()

    # ── Build summary ──
    report.summary = {
        "input": query,
        "input_type": input_type.value,
        "total_tools_in_framework": len(all_tools),
        "tools_searched": report.total_tools_searched,
        "tools_with_matches": report.tools_with_matches,
        "total_matches": report.total_matches,
        "deep_crawl_pages": len(report.deep_crawl_results),
        "deep_crawl_total_matches": sum(cr["matches"] for cr in report.deep_crawl_results),
        "results_by_status": {
            "success": sum(1 for r in report.results if r.status == "success"),
            "no_match": sum(1 for r in report.results if r.status == "no_match"),
            "blocked": sum(1 for r in report.results if r.status == "blocked"),
            "error": sum(1 for r in report.results if r.status == "error"),
        },
        "results_by_category": defaultdict(int),
    }
    for r in report.results:
        if r.match_count > 0:
            report.summary["results_by_category"][r.category] += r.match_count

    return report


# ═══════════════════════════════════════════════════════
# 9. REPORT PRINTING
# ═══════════════════════════════════════════════════════
def print_report(report: FullOSINTReport):
    s = report.summary
    print("\n" + "█" * 75)
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║              FULL OSINT FRAMEWORK SEARCH REPORT              ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print(f"  Input:           {report.input_value}")
    print(f"  Input Type:      {report.input_type.value}")
    print(f"  Framework Size:  {s['total_tools_in_framework']} total tools")
    print(f"  Tools Searched:  {s['tools_searched']}")
    print(f"  Tools w/ Matches:{s['tools_with_matches']}")
    print(f"  Total Matches:   {s['total_matches']}")
    print(f"  Deep Crawl:      {s['deep_crawl_pages']} pages, {s['deep_crawl_total_matches']} matches")
    print("  " + "─" * 71)
    print("  STATUS BREAKDOWN:")
    for status, count in s["results_by_status"].items():
        bar = "█" * count
        print(f"    {status:12s}: {count:4d} {bar}")
    print("  " + "─" * 71)
    if s["results_by_category"]:
        print("  MATCHES BY CATEGORY:")
        for cat, count in sorted(s["results_by_category"].items(), key=lambda x: -x[1]):
            print(f"    {cat:40s}: {count}")
    print("█" * 75)

    print("\n  DETAILED RESULTS (tools with matches):")
    print("  " + "─" * 71)
    for r in sorted(report.results, key=lambda x: -x.match_count):
        if r.match_count > 0:
            print(f"  ✅ {r.tool_name:35s} | {r.match_count:5d} | {r.category}")
            for d in r.match_details[:3]:
                print(f"     → {d}")
            print(f"     URL: {r.url_searched[:90]}")
            print()

    print("  TOOLS WITH NO MATCHES (summary):")
    print("  " + "─" * 71)
    no_match = [r for r in report.results if r.match_count == 0]
    print(f"  {len(no_match)} tools returned no matches.")
    blocked = [r for r in report.results if r.status == "blocked"]
    errors = [r for r in report.results if r.status == "error"]
    if blocked:
        print(f"  Blocked ({len(blocked)}): {[r.tool_name for r in blocked[:10]]}")
    if errors:
        print(f"  Errors ({len(errors)}): {[r.tool_name for r in errors[:10]]}")

    if report.deep_crawl_results:
        print("\n  DEEP CRAWL RESULTS:")
        print("  " + "─" * 71)
        for cr in sorted(report.deep_crawl_results, key=lambda x: -x["matches"]):
            print(f"  [D{cr['depth']}] {cr['matches']:4d} matches — {cr['url'][:80]}")

    print("\n" + "█" * 75)


# ═══════════════════════════════════════════════════════
# 10. CLI
# ═══════════════════════════════════════════════════════
async def main():
    import sys

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║         FULL OSINT FRAMEWORK AUTOMATED SEARCHER              ║
    ║  Fetches live tree from GitHub → detects input → searches   ║
    ║  every relevant tool → counts all matches → deep crawls     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    if len(sys.argv) < 2:
        query = input("Enter search query (phone, email, SSN, name, username, domain, IP, hash, BTC addr): ").strip()
    else:
        query = sys.argv[1]

    if not query:
        print("Error: No query provided.")
        return

    deep_crawl = "--deep" in sys.argv
    visible = "--visible" in sys.argv
    limit = None
    for i, arg in enumerate(sys.argv):
        if arg == "--limit" and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
    delay = 1.5
    for i, arg in enumerate(sys.argv):
        if arg == "--delay" and i + 1 < len(sys.argv):
            delay = float(sys.argv[i + 1])

    report = await run_full_osint_search(
        query,
        deep_crawl=deep_crawl,
        headless=not visible,
        max_tools=limit,
        delay_between=delay
    )
    print_report(report)


if __name__ == "__main__":
    asyncio.run(main())