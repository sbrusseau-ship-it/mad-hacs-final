# osint_parallel_searcher.py
# pip install playwright requests
# python -m playwright install chromium

import asyncio
import json
import re
import logging
import os
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Tuple
from urllib.parse import urlparse, quote
from collections import defaultdict

import requests
from playwright.async_api import async_playwright, Page, BrowserContext

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("osint_parallel")


# ═══════════════════════════════════════════════════════
# 1. FETCH OSINT FRAMEWORK TREE
# ═══════════════════════════════════════════════════════
OSINT_JSON_URL = "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json"


def fetch_osint_tree() -> dict:
    log.info("Fetching OSINT Framework tree from GitHub...")
    resp = requests.get(OSINT_JSON_URL, timeout=15)
    resp.raise_for_status()
    return resp.json()


@dataclass
class Tool:
    name: str
    url: str
    category_path: str
    parent_category: str


def flatten_tree(node: dict, path: str = "", tools: list = None) -> list:
    if tools is None:
        tools = []
    node_name = node.get("name", "Unknown")
    node_type = node.get("type", "folder")
    node_url = node.get("url", "")
    current_path = f"{path} > {node_name}" if path else node_name

    if node_type == "url" and node_url:
        top_cat = path.split(" > ")[0] if " > " in path else node_name
        tools.append(Tool(
            name=node_name, url=node_url,
            category_path=current_path, parent_category=top_cat
        ))
    elif node_type == "folder" and "children" in node:
        for child in node["children"]:
            flatten_tree(child, current_path, tools)
    return tools


# ═══════════════════════════════════════════════════════
# 2. INPUT TYPE DETECTION
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
    DOB = "dob"
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
    if re.match(r"^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$", v) or re.match(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}$", v):
        return InputType.DOB
    if re.match(r"^[a-zA-Z0-9_.]{3,30}$", v) and " " not in v:
        return InputType.USERNAME
    if re.match(r"^[A-Za-z]+(?:\s+[A-Za-z]+)+$", v):
        return InputType.NAME
    return InputType.UNKNOWN


# ═══════════════════════════════════════════════════════
# 3. CATEGORY MAPPING
# ═══════════════════════════════════════════════════════
CATEGORY_MAP = {
    InputType.PHONE_US: ["Telephone Numbers", "Public Records", "People Search Engines",
                         "Social Networks", "Dating", "Compliance & Risk Intelligence"],
    InputType.PHONE_INTL: ["Telephone Numbers", "Public Records", "People Search Engines",
                           "Social Networks", "Compliance & Risk Intelligence"],
    InputType.EMAIL: ["Email Address", "Social Networks", "Username", "Breach Data",
                      "People Search Engines", "Domain Name"],
    InputType.USERNAME: ["Username", "Social Networks", "Online Communities",
                         "Gaming", "Dating", "People Search Engines"],
    InputType.DOMAIN: ["Domain Name", "Cloud Infrastructure", "IP & MAC Address",
                       "Search Engines", "Archives"],
    InputType.IP_ADDRESS: ["IP & MAC Address", "Geolocation Tools / Maps",
                           "Cloud Infrastructure", "Search Engines"],
    InputType.NAME: ["People Search Engines", "Public Records", "Social Networks",
                     "Dating", "Business Records", "Compliance & Risk Intelligence"],
    InputType.SSN: ["Public Records", "Compliance & Risk Intelligence", "People Search Engines"],
    InputType.DOB: ["Public Records", "People Search Engines", "Business Records"],
    InputType.URL_LINK: ["Search Engines", "Archives", "Social Networks",
                         "Disinformation & Media Verification"],
    InputType.HASH: ["Encoding / Decoding", "Search Engines", "Blockchain & Cryptocurrency"],
    InputType.BITCOIN_ADDR: ["Blockchain & Cryptocurrency", "Search Engines"],
    InputType.UNKNOWN: [],
}


def get_relevant_tools(all_tools: list, input_type: InputType) -> list:
    categories = CATEGORY_MAP.get(input_type, [])
    if not categories:
        log.warning(f"Unknown input type — searching ALL {len(all_tools)} tools")
        return all_tools
    relevant = []
    for tool in all_tools:
        for cat in categories:
            if cat.lower() in tool.category_path.lower() or cat.lower() in tool.parent_category.lower():
                relevant.append(tool)
                break
    return relevant


# ═══════════════════════════════════════════════════════
# 4. SEARCH URL BUILDER
# ═══════════════════════════════════════════════════════
def build_search_url(tool: Tool, query: str) -> str:
    url = tool.url.rstrip("/")
    domain = urlparse(url).netloc
    q = quote(query)

    patterns = {
        "namechk.com": f"https://namechk.com/en/search?q={q}",
        "knowem.com": f"https://knowem.com/search/{q}",
        "usersearch.org": f"https://usersearch.org/results.php?username={q}",
        "whatsmyname.app": f"https://whatsmyname.app/?q={q}",
        "haveibeenpwned.com": f"https://haveibeenpwned.com/unifiedsearch/{q}",
        "hunter.io": f"https://hunter.io/email-finder/{q}",
        "emailrep.io": f"https://emailrep.io/{q}",
        "gravatar.com": f"https://en.gravatar.com/{q}",
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
        "domaintools.com": f"https://whois.domaintools.com/{q}",
        "dnslytics.com": f"https://dnslytics.com/domain/{q}",
        "viewdns.info": f"https://viewdns.info/whois/?domain={q}",
        "securitytrails.com": f"https://securitytrails.com/domain/{q}",
        "whois.com": f"https://www.whois.com/whois/{q}",
        "ipinfo.io": f"https://ipinfo.io/{q}",
        "abuseipdb.com": f"https://www.abuseipdb.com/check/{q}",
        "virustotal.com": f"https://www.virustotal.com/gui/ip-address/{q}",
        "shodan.io": f"https://www.shodan.io/host/{q}",
        "censys.io": f"https://search.censys.io/hosts/{q}",
        "truepeoplesearch.com": f"https://www.truepeoplesearch.com/results?name={q}",
        "fastpeoplesearch.com": f"https://www.fastpeoplesearch.com/search?q={q}",
        "cubib.com": f"https://cubib.com/search?name={q}",
        "thatsthem.com": f"https://thatsthem.com/name/{q.replace(' ', '-')}",
        "spokeo.com": f"https://www.spokeo.com/name/{q.replace(' ', '-')}",
        "ssnvalidator.com": f"https://www.ssnvalidator.com/ssn/{q}",
        "ssncheck.com": f"https://www.ssncheck.com/{q}",
        "blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{q}",
        "blockchair.com": f"https://blockchair.com/bitcoin/address/{q}",
        "mempool.space": f"https://mempool.space/address/{q}",
        "md5decrypt.net": f"https://www.md5decrypt.net/en/Sha256/#input={q}",
        "crackstation.net": f"https://crackstation.net/?c={q}",
        "google.com": f"https://www.google.com/search?q={q}",
        "bing.com": f"https://www.bing.com/search?q={q}",
        "duckduckgo.com": f"https://duckduckgo.com/?q={q}",
        "yandex.com": f"https://yandex.com/search/?text={q}",
        "archive.org": f"https://web.archive.org/web/*/{q}",
    }

    for pattern_domain, pattern_url in patterns.items():
        if pattern_domain in domain:
            return pattern_url

    if "/search" in url or "/lookup" in url or "/find" in url:
        return f"{url}?q={q}" if "?" not in url else f"{url}&q={q}"
    return url


# ═══════════════════════════════════════════════════════
# 5. PAGE ANALYSIS
# ═══════════════════════════════════════════════════════
@dataclass
class ToolResult:
    input_value: str
    input_type: str
    tool_name: str
    category: str
    url_searched: str
    status: str
    match_count: int = 0
    match_details: list = field(default_factory=list)
    error: Optional[str] = None


async def analyze_page(page: Page, tool: Tool, query: str, input_type: InputType) -> ToolResult:
    search_url = build_search_url(tool, query)

    try:
        log.info(f"    🌐 Navigating to: {search_url[:100]}")
        response = await page.goto(search_url, wait_until="domcontentloaded", timeout=20000)

        if response and response.status >= 400:
            log.info(f"    ❌ Blocked (HTTP {response.status})")
            return ToolResult(
                input_value=query, input_type=input_type.value,
                tool_name=tool.name, category=tool.parent_category,
                url_searched=search_url, status="blocked",
                error=f"HTTP {response.status}"
            )

        log.info(f"    ⏳ Waiting 2.5s for page to load...")
        await page.wait_for_timeout(2500)

        match_count = 0
        match_details = []

        # ── CHECK 1: Body text scan ──
        log.info(f"    🔍 CHECK 1: Scanning body text for '{query}'...")
        try:
            body_text = await page.evaluate("() => document.body.innerText")
            text_occ = len(re.findall(re.escape(query), body_text, re.IGNORECASE))
            if text_occ > 0:
                match_count += text_occ
                match_details.append(f"Text matches: {text_occ}")
                log.info(f"       ✅ Found {text_occ} text matches in body")
            else:
                log.info(f"       ❌ No text matches in body")
        except Exception as e:
            log.info(f"       ⚠️  Error: {e}")

        # ── CHECK 2: HTML source scan ──
        log.info(f"    🔍 CHECK 2: Scanning HTML source for '{query}'...")
        try:
            html = await page.evaluate("() => document.documentElement.outerHTML")
            html_occ = len(re.findall(re.escape(query), html, re.IGNORECASE))
            if html_occ > 0:
                match_count += html_occ
                match_details.append(f"HTML matches: {html_occ}")
                log.info(f"       ✅ Found {html_occ} HTML matches")
            else:
                log.info(f"       ❌ No HTML matches")
        except Exception as e:
            log.info(f"       ⚠️  Error: {e}")

        # ── CHECK 3: Link scanning ──
        log.info(f"    🔍 CHECK 3: Scanning all links on page...")
        try:
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a')).map(a => ({
                    href: a.href, text: a.innerText
                }))
            """)
            q_clean = query.replace(" ", "").replace("-", "").replace(".", "").lower()
            matching = [l for l in links
                        if q_clean in l.get("href", "").replace(" ", "").replace("-", "").replace(".", "").lower()
                        or q_clean in l.get("text", "").replace(" ", "").replace("-", "").replace(".", "").lower()]
            if matching:
                match_count += len(matching)
                match_details.append(f"Matching links: {len(matching)}")
                log.info(f"       ✅ Found {len(matching)} matching links")
                for link in matching[:3]:
                    log.info(f"          → {link.get('href', '')[:80]}")
            else:
                log.info(f"       ❌ No matching links")
        except Exception as e:
            log.info(f"       ⚠️  Error: {e}")

        # ── CHECK 4: CSS selector scanning ──
        log.info(f"    🔍 CHECK 4: Testing CSS selectors for result containers...")
        selectors = [
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
        
        for sel in selectors:
            try:
                elements = await page.query_selector_all(sel)
                if elements and len(elements) > 0:
                    log.info(f"       📦 Selector '{sel}' found {len(elements)} elements, checking for matches...")
                    has_match = False
                    for el in elements[:20]:
                        text = await el.inner_text()
                        if query.lower() in text.lower():
                            has_match = True
                            break
                    if has_match:
                        match_count += len(elements)
                        match_details.append(f"Selector '{sel}': {len(elements)} elements with match")
                        log.info(f"          ✅ MATCH FOUND in {len(elements)} elements!")
                        break
                    else:
                        log.info(f"          ❌ No query match in these elements")
            except Exception:
                pass

        # ── CHECK 5: Meta tags and title ──
        log.info(f"    🔍 CHECK 5: Checking page title and meta tags...")
        try:
            title = await page.title()
            if query.lower() in title.lower():
                match_count += 1
                match_details.append(f"Match in title: {title}")
                log.info(f"       ✅ Match in page title: {title}")
            
            meta_desc = await page.evaluate("""
                () => document.querySelector('meta[name="description"]')?.content || ''
            """)
            if query.lower() in meta_desc.lower():
                match_count += 1
                match_details.append("Match in meta description")
                log.info(f"       ✅ Match in meta description")
        except Exception as e:
            log.info(f"       ⚠️  Error: {e}")

        # ── Final result ──
        if match_count > 0:
            log.info(f"    ✅ TOTAL: {match_count} matches found across all checks")
        else:
            log.info(f"    ❌ TOTAL: No matches found")

        status = "success" if match_count > 0 else "no_match"

        return ToolResult(
            input_value=query, input_type=input_type.value,
            tool_name=tool.name, category=tool.parent_category,
            url_searched=search_url, status=status,
            match_count=match_count, match_details=match_details
        )

    except Exception as e:
        log.info(f"    💥 ERROR: {str(e)[:150]}")
        return ToolResult(
            input_value=query, input_type=input_type.value,
            tool_name=tool.name, category=tool.parent_category,
            url_searched=search_url, status="error",
            error=str(e)[:200]
        )

# ═══════════════════════════════════════════════════════
# 6. PARALLEL SEARCH FOR ONE QUERY
# ═══════════════════════════════════════════════════════
async def search_one_query(
    query: str,
    input_type: InputType,
    relevant_tools: list,
    browser,
    semaphore: asyncio.Semaphore,
    delay: float
) -> List[ToolResult]:
    """Search one query across all its relevant tools, with concurrency limiting."""
    results = []

    async def search_tool(tool: Tool) -> ToolResult:
        async with semaphore:
            page = await browser.new_page()
            try:
                result = await analyze_page(page, tool, query, input_type)
                return result
            finally:
                await page.close()
                await asyncio.sleep(delay)

    log.info(f"\n{'='*60}")
    log.info(f"QUERY: '{query}' (type: {input_type.value}) → {len(relevant_tools)} tools")
    log.info(f"{'='*60}")

    tasks = [search_tool(tool) for tool in relevant_tools]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    clean_results = []
    for r in results:
        if isinstance(r, Exception):
            log.error(f"  Exception: {r}")
        else:
            clean_results.append(r)
            if r.match_count > 0:
                log.info(f"  ✅ {r.tool_name}: {r.match_count} matches")
            else:
                log.info(f"  ❌ {r.tool_name}: {r.status}")

    return clean_results


# ═══════════════════════════════════════════════════════
# 7. INTERACTIVE INPUT PROMPT
# ═══════════════════════════════════════════════════════
def prompt_inputs() -> List[Tuple[str, InputType]]:
    """Ask user for each field line by line. Return list of (value, type) for non-empty."""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║         OSINT MULTI-INPUT PARALLEL SEARCHER                  ║
    ║  Enter details for each field. Press ENTER to skip a field.  ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    fields = [
        ("Name", None),
        ("Date of Birth (MM/DD/YYYY)", InputType.DOB),
        ("SSN (XXX-XX-XXXX)", InputType.SSN),
        ("Email", InputType.EMAIL),
        ("Phone Number", None),
        ("Username", InputType.USERNAME),
        ("Domain", InputType.DOMAIN),
        ("IP Address", InputType.IP_ADDRESS),
        ("Bitcoin Address", InputType.BITCOIN_ADDR),
        ("Hash (MD5/SHA1/SHA256)", InputType.HASH),
        ("URL", InputType.URL_LINK),
    ]

    queries = []
    for label, forced_type in fields:
        value = input(f"{label}: ").strip()
        if value:
            if forced_type:
                itype = forced_type
            else:
                itype = detect_input_type(value)
            queries.append((value, itype))
            print(f"   → Detected as: {itype.value}")

    if not queries:
        print("\n❌ No inputs provided. Exiting.")
        return []

    print(f"\n✅ {len(queries)} input(s) queued for parallel search:")
    for v, t in queries:
        print(f"   • '{v}' ({t.value})")

    return queries


# ═══════════════════════════════════════════════════════
# 8. MAIN ORCHESTRATOR — PARALLEL
# ═══════════════════════════════════════════════════════
async def run_parallel_osint_search(
    queries: List[Tuple[str, InputType]],
    all_tools: list,
    headless: bool = True,
    max_concurrent: int = 3,
    delay_between: float = 1.0
) -> dict:
    """
    Run all queries in parallel. Each query gets its own set of relevant tools.
    Returns: { "2d_array": [[input, website], ...], "summary": {...}, "results": [...] }
    """
    semaphore = asyncio.Semaphore(max_concurrent)

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
        )

        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            window.chrome = { runtime: {} };
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        """)

        # Launch parallel searches for all queries
        tasks = []
        for query, input_type in queries:
            relevant = get_relevant_tools(all_tools, input_type)
            tasks.append(search_one_query(query, input_type, relevant, browser, semaphore, delay_between))

        all_results = await asyncio.gather(*tasks)

        await browser.close()

    # Flatten results
    flat_results = []
    for query_results in all_results:
        flat_results.extend(query_results)

    # Build 2D array: [[input_value, website_name], ...]
    two_d_array = []
    for r in flat_results:
        if r.match_count > 0:
            two_d_array.append([r.input_value, r.tool_name])

    # Build summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_queries": len(queries),
        "queries": [{"value": q, "type": t.value} for q, t in queries],
        "total_tools_searched": len(flat_results),
        "tools_with_matches": sum(1 for r in flat_results if r.match_count > 0),
        "total_matches": sum(r.match_count for r in flat_results),
        "two_d_array_size": len(two_d_array),
        "results_by_status": {
            "success": sum(1 for r in flat_results if r.status == "success"),
            "no_match": sum(1 for r in flat_results if r.status == "no_match"),
            "blocked": sum(1 for r in flat_results if r.status == "blocked"),
            "error": sum(1 for r in flat_results if r.status == "error"),
        },
    }

    return {
        "2d_array": two_d_array,
        "summary": summary,
        "all_results": flat_results,
    }


# ═══════════════════════════════════════════════════════
# 9. SAVE TO TEXT FILE
# ═══════════════════════════════════════════════════════
def save_report(data: dict, filename: str = "osint_report.txt"):
    """Save 2D array + summary to a text file."""
    two_d = data["2d_array"]
    summary = data["summary"]
    results = data["all_results"]

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 75 + "\n")
        f.write("  OSINT PARALLEL SEARCH REPORT\n")
        f.write(f"  Generated: {summary['timestamp']}\n")
        f.write("=" * 75 + "\n\n")

        f.write("QUERIES:\n")
        for q in summary["queries"]:
            f.write(f"  • {q['value']} ({q['type']})\n")
        f.write("\n")

        f.write("SUMMARY:\n")
        f.write(f"  Total queries:        {summary['total_queries']}\n")
        f.write(f"  Total tools searched: {summary['total_tools_searched']}\n")
        f.write(f"  Tools with matches:   {summary['tools_with_matches']}\n")
        f.write(f"  Total matches:        {summary['total_matches']}\n")
        f.write(f"  2D array entries:     {summary['two_d_array_size']}\n")
        f.write("\n")

        f.write("STATUS BREAKDOWN:\n")
        for status, count in summary["results_by_status"].items():
            f.write(f"  {status:12s}: {count}\n")
        f.write("\n")

        f.write("=" * 75 + "\n")
        f.write("  2D ARRAY: [input_value, website_name]\n")
        f.write("=" * 75 + "\n\n")

        if two_d:
            f.write("[\n")
            for i, row in enumerate(two_d):
                comma = "," if i < len(two_d) - 1 else ""
                f.write(f"  [\"{row[0]}\", \"{row[1]}\"]{comma}\n")
            f.write("]\n\n")
        else:
            f.write("[]  (no matches found)\n\n")

        f.write("=" * 75 + "\n")
        f.write("  DETAILED RESULTS (tools with matches)\n")
        f.write("=" * 75 + "\n\n")

        matched = [r for r in results if r.match_count > 0]
        for r in sorted(matched, key=lambda x: -x.match_count):
            f.write(f"✅ {r.input_value:30s} | {r.tool_name:35s} | {r.match_count} matches\n")
            f.write(f"   Category: {r.category}\n")
            f.write(f"   URL: {r.url_searched}\n")
            for d in r.match_details[:3]:
                f.write(f"   → {d}\n")
            f.write("\n")

        f.write("=" * 75 + "\n")
        f.write("  TOOLS WITH NO MATCHES\n")
        f.write("=" * 75 + "\n\n")

        no_match = [r for r in results if r.match_count == 0]
        f.write(f"{len(no_match)} tools returned no matches.\n")

        blocked = [r for r in results if r.status == "blocked"]
        errors = [r for r in results if r.status == "error"]
        if blocked:
            f.write(f"\nBlocked ({len(blocked)}):\n")
            for r in blocked:
                f.write(f"  • {r.tool_name} — {r.error}\n")
        if errors:
            f.write(f"\nErrors ({len(errors)}):\n")
            for r in errors:
                f.write(f"  • {r.tool_name} — {r.error}\n")

    log.info(f"\n📄 Report saved to: {os.path.abspath(filename)}")


def print_2d_array(two_d_array: list):
    """Pretty-print the 2D array."""
    print("\n" + "█" * 75)
    print("  2D ARRAY: [input_value, website_name]")
    print("█" * 75)
    if two_d_array:
        print("[")
        for row in two_d_array:
            print(f"  [\"{row[0]}\", \"{row[1]}\"],")
        print("]")
    else:
        print("[]  (no matches)")
    print("█" * 75)


# ═══════════════════════════════════════════════════════
# 10. CLI
# ═══════════════════════════════════════════════════════
async def main():
    import sys

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║      FULL OSINT FRAMEWORK — PARALLEL MULTI-INPUT SEARCH      ║
    ║  • Fetches live tree from GitHub (~700 tools)                ║
    ║  • Prompts for multiple inputs (name, DOB, SSN, email...)    ║
    ║  • Searches ALL inputs in PARALLEL                           ║
    ║  • Outputs 2D array: [[input, website], ...]                 ║
    ║  • Saves full report to osint_report.txt                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    # Fetch framework tree
    tree = fetch_osint_tree()
    all_tools = flatten_tree(tree)
    log.info(f"Loaded {len(all_tools)} tools from OSINT Framework")

    # Parse CLI args
    headless = not ("--visible" in sys.argv)
    max_concurrent = 3
    delay = 1.0
    for i, arg in enumerate(sys.argv):
        if arg == "--concurrent" and i + 1 < len(sys.argv):
            max_concurrent = int(sys.argv[i + 1])
        if arg == "--delay" and i + 1 < len(sys.argv):
            delay = float(sys.argv[i + 1])

    # Prompt for inputs
    queries = prompt_inputs()
    if not queries:
        return

    # Run parallel search
    data = await run_parallel_osint_search(
        queries, all_tools,
        headless=headless,
        max_concurrent=max_concurrent,
        delay_between=delay
    )

    # Print 2D array
    print_2d_array(data["2d_array"])

    # Print summary
    s = data["summary"]
    print(f"\n  Queries:        {s['total_queries']}")
    print(f"  Tools searched: {s['total_tools_searched']}")
    print(f"  With matches:   {s['tools_with_matches']}")
    print(f"  Total matches:  {s['total_matches']}")
    print(f"  2D array size:  {s['two_d_array_size']}")

    # Save to file
    save_report(data, "osint_report.txt")

    print("\n✅ Done! Check osint_report.txt on your Desktop.")


if __name__ == "__main__":
    asyncio.run(main())