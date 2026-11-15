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
from urllib.parse import urlparse, quote, parse_qsl, urlencode, urlunparse
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
    tree_file = os.environ.get("OSINT_TREE_FILE")
    if tree_file:
        with open(tree_file, encoding="utf-8") as source:
            return json.load(source)
    resp = requests.get(os.environ.get("OSINT_TREE_URL", OSINT_JSON_URL), timeout=15)
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
        categories = path.split(" > ")
        top_cat = categories[1] if len(categories) > 1 else categories[0]
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
    ADDRESS = "address"
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
    InputType.ADDRESS: ["Public Records", "People Search Engines", "Geolocation Tools / Maps"],
    InputType.UNKNOWN: [],
}


def is_project_reference(url: str) -> bool:
    """Repository/docs pages describe a tool; visiting them does not run it."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in {"raw.githubusercontent.com", "gist.github.com"} or host.endswith(".github.io"):
        return True
    if host in {"github.com", "www.github.com"}:
        parts = [part for part in parsed.path.split("/") if part]
        return len(parts) >= 2 and parts[0] not in {"search", "topics", "collections", "marketplace"}
    return False


def get_relevant_tools(all_tools: list, input_type: InputType) -> list:
    all_tools = [tool for tool in all_tools if not is_project_reference(tool.url)]
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
    domain = (urlparse(url).hostname or "").lower()
    q = quote(query, safe="")

    # Catalog URLs can be search templates, including site-restricted dorks.
    # Substitute their parameter values before generic domain routing.
    parsed = urlparse(url)
    parameters = parse_qsl(parsed.query, keep_blank_values=True)
    template = re.compile(r"<(?:username|searchterm|email_address|domain\.com|user_id)>", re.I)
    if any(template.search(value) for _, value in parameters):
        parameters = [(key, template.sub(lambda _: query, value)) for key, value in parameters]
        return urlunparse(parsed._replace(query=urlencode(parameters)))
    if domain in {"google.com", "www.google.com", "bing.com", "www.bing.com", "duckduckgo.com", "yandex.com"} and any(key == "q" for key, _ in parameters):
        parameters = [(key, f"{value} {query}" if key == "q" else value) for key, value in parameters]
        return urlunparse(parsed._replace(query=urlencode(parameters)))

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
        if domain == pattern_domain or domain.endswith("." + pattern_domain):
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
    source_url: Optional[str] = None
    final_url: Optional[str] = None
    backend: str = "browser"


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
        await page.wait_for_timeout(int(os.environ.get("OSINT_PAGE_WAIT_MS", "2500")))

        final_url = page.url
        host = (urlparse(final_url).hostname or "").lower()
        search_hosts = ("google.com", "bing.com", "duckduckgo.com", "yandex.com", "yahoo.com")
        if any(host == engine or host.endswith("." + engine) for engine in search_hosts):
            return ToolResult(
                input_value=query, input_type=input_type.value,
                tool_name=tool.name, category=tool.parent_category,
                url_searched=search_url, status="manual_review",
                match_details=["Search engine query only. Review individual result pages; query echoes are not evidence of an account or exposure."],
                source_url=tool.url, final_url=final_url,
            )

        # Count visible content once. HTML, titles, form values and navigation
        # often repeat the query and must not inflate occurrence counts.
        body_text = await page.evaluate("""() => {
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            const text = [];
            while (walker.nextNode()) {
                const parent = walker.currentNode.parentElement;
                if (!parent || parent.closest('script,style,noscript,template,form,input,textarea,nav,header,footer,[role="search"],[hidden]')) continue;
                if (!parent.getClientRects().length || getComputedStyle(parent).visibility === 'hidden') continue;
                text.push(walker.currentNode.textContent);
            }
            return text.join(' ');
        }""")
        match_count = len(re.findall(re.escape(query), body_text, re.IGNORECASE))
        match_details = [f"Visible content occurrences: {match_count}"] if match_count else []
        status = "success" if match_count > 0 else "no_match"

        return ToolResult(
            input_value=query, input_type=input_type.value,
            tool_name=tool.name, category=tool.parent_category,
            url_searched=search_url, status=status,
            match_count=match_count, match_details=match_details,
            source_url=tool.url, final_url=final_url
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
    delay: float,
    on_result=None,
    source_timeout: float = 30.0,
) -> List[ToolResult]:
    """Search one query across all its relevant tools, with concurrency limiting."""
    results = []

    async def search_tool(tool: Tool) -> ToolResult:
        async with semaphore:
            page = None
            try:
                async def inspect():
                    nonlocal page
                    page = await browser.new_page()
                    return await analyze_page(page, tool, query, input_type)

                result = await asyncio.wait_for(inspect(), timeout=source_timeout)
            except Exception as exc:
                result = ToolResult(
                    input_value=query, input_type=input_type.value,
                    tool_name=tool.name, category=tool.parent_category,
                    url_searched=build_search_url(tool, query), status="error",
                    error="Source timed out." if isinstance(exc, asyncio.TimeoutError) else "Source could not be inspected.",
                    source_url=tool.url,
                )
            finally:
                if page is not None:
                    try:
                        await asyncio.wait_for(page.close(), timeout=5)
                    except Exception:
                        pass
            if on_result:
                on_result(result)
            if delay:
                await asyncio.sleep(delay)
            return result

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
    max_concurrent: int = 8,
    delay_between: float = 1.0,
    max_tools_per_query: Optional[int] = None,
    on_result=None,
    on_plan=None,
    source_timeout: float = 30.0,
) -> dict:
    """
    Run all queries in parallel. Each query gets its own set of relevant tools.
    Returns: { "2d_array": [[input, website], ...], "summary": {...}, "results": [...] }
    """
    if not 1 <= max_concurrent <= 32 or source_timeout <= 0:
        raise ValueError("Concurrency must be 1–32 and source timeout must be positive")
    plan = []
    for query, input_type in queries:
        relevant = get_relevant_tools(all_tools, input_type)
        if max_tools_per_query is not None:
            relevant = relevant[:max_tools_per_query]
        plan.append((query, input_type, relevant))
    planned_count = sum(len(relevant) for _, _, relevant in plan)
    if on_plan:
        on_plan(planned_count)
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
        for query, input_type, relevant in plan:
            tasks.append(search_one_query(query, input_type, relevant, context, semaphore, delay_between, on_result, source_timeout))

        try:
            all_results = await asyncio.gather(*tasks)
        finally:
            await browser.close()

    # Flatten results
    flat_results = []
    for query_results in all_results:
        flat_results.extend(query_results)

    return summarize_results(queries, flat_results, planned_count)


def summarize_results(queries, flat_results, planned_count):
    """Use identical counts for streamed snapshots and the final result."""
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
        "total_tools_planned": planned_count,
        "tools_with_matches": sum(1 for r in flat_results if r.match_count > 0),
        "total_matches": sum(r.match_count for r in flat_results),
        "two_d_array_size": len(two_d_array),
        "results_by_status": {
            "success": sum(1 for r in flat_results if r.status == "success"),
            "no_match": sum(1 for r in flat_results if r.status == "no_match"),
            "blocked": sum(1 for r in flat_results if r.status == "blocked"),
            "error": sum(1 for r in flat_results if r.status == "error"),
            "manual_review": sum(1 for r in flat_results if r.status == "manual_review"),
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
