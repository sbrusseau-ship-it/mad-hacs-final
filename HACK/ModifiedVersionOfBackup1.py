# osint_full_framework.py
# pip install playwright requests
# playwright install chromium

import asyncio
import csv
import json
import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, quote, quote_plus
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
        tools.append(Tool(name=node_name, url=node_url,
                          category_path=current_path, parent_category=top_cat))
    elif node_type == "folder" and "children" in node:
        for child in node["children"]:
            flatten_tree(child, current_path, tools)
    return tools


# ═══════════════════════════════════════════════════════
# 3. INPUT TYPE DETECTION  (now includes ADDRESS)
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
    ADDRESS = "address"          # <-- NEW
    URL_LINK = "url_link"
    HASH = "hash"
    BITCOIN_ADDR = "bitcoin_address"
    UNKNOWN = "unknown"


STREET_RE = re.compile(
    r"\d+\s+\w+(\s\w+)*\s+(st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|ln|lane|"
    r"way|ct|court|pkwy|parkway|hwy|highway|pl|place|ter|terrace|cir|circle|sq|square)\b",
    re.IGNORECASE)


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
    if STREET_RE.search(v):                     # <-- NEW: address heuristic
        return InputType.ADDRESS
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
    InputType.ADDRESS: [                          # <-- NEW
        "Geolocation Tools / Maps", "Public Records",
        "People Search Engines", "Business Records",
        "Compliance & Risk Intelligence"
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
    InputType.UNKNOWN: [],
}


def get_relevant_tools(all_tools: list, input_type: InputType) -> list:
    categories = CATEGORY_MAP.get(input_type, [])
    if not categories:
        log.warning("Unknown input type — will search ALL tools in the framework")
        return all_tools
    relevant = []
    for tool in all_tools:
        for cat in categories:
            if cat.lower() in tool.category_path.lower() or cat.lower() in tool.parent_category.lower():
                relevant.append(tool)
                break
    log.info(f"Input type '{input_type.value}' → {len(relevant)} tools across categories: {categories}")
    return relevant


# ═══════════════════════════════════════════════════════
# 5. SEARCH URL CONSTRUCTION (address patterns added)
# ═══════════════════════════════════════════════════════
def build_search_url(tool: Tool, query: str) -> str:
    url = tool.url.rstrip("/")
    domain = urlparse(url).netloc
    q = quote(query)
    q_hyphen = quote_plus(query.replace(" ", "-"))

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
        # Address
        "google.com": f"https://www.google.com/maps/search/?api=1&query={q}",
        "bing.com": f"https://www.bing.com/maps?q={q}",
        "whitepages.com/rev": "",  # placeholder, real one below
        "zillow.com": f"https://www.zillow.com/homes/{q_hyphen}_rb/",
        "realtor.com": f"https://www.realtor.com/realestateandhomes-search/{quote_plus(query)}",
        "familytreenow.com": f"https://www.familytreenow.com/search/records/genealogy/results?address={q}",
        # Bitcoin
        "blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{q}",
        "blockchair.com": f"https://blockchair.com/bitcoin/address/{q}",
        "mempool.space": f"https://mempool.space/address/{q}",
        # Hash
        "md5decrypt.net": f"https://www.md5decrypt.net/en/Sha256/#input={q}",
        "crackstation.net": f"https://crackstation.net/?c={q}",
        # General
        "duckduckgo.com": f"https://duckduckgo.com/?q={q}",
        "yandex.com": f"https://yandex.com/search/?text={q}",
        "waybackmachine.org": f"https://web.archive.org/web/*/{q}",
        "archive.org": f"https://web.archive.org/web/*/{q}",
    }

    for pattern_domain, pattern_url in patterns.items():
        if pattern_domain in domain and pattern_url:
            return pattern_url

    if "/search" in url or "/lookup" in url or "/find" in url:
        return f"{url}?q={q}" if "?" not in url else f"{url}&q={q}"
    return url


# ═══════════════════════════════════════════════════════
# 6. PAGE ANALYSIS & MATCH COUNTING  (unchanged)
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
    search_url = build_search_url(tool, query)
    try:
        log.info(f"  → {tool.name}: {search_url[:80]}...")
        response = await page.goto(search_url, wait_until="domcontentloaded", timeout=20000)
        if response and response.status >= 400:
            return ToolResult(tool_name=tool.name, category=tool.parent_category,
                              url_searched=search_url, status="blocked", error=f"HTTP {response.status}")
        await page.wait_for_timeout(3000)
        page_title = await page.title()
        match_count = 0
        match_details = []

        try:
            body_text = await page.evaluate("() => document.body.innerText")
            n = len(re.findall(re.escape(query), body_text, re.IGNORECASE))
            if n:
                match_count += n
                match_details.append(f"Text matches: {n}")
        except Exception:
            pass

        try:
            html = await page.evaluate("() => document.documentElement.outerHTML")
            n = len(re.findall(re.escape(query), html, re.IGNORECASE))
            if n:
                match_count += n
                match_details.append(f"HTML matches: {n}")
        except Exception:
            pass

        try:
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a')).map(a => ({href: a.href, text: a.innerText}))
            """)
            qc = query.replace(" ", "").replace("-", "").replace(".", "").lower()
            hits = [l for l in links
                    if qc in (l.get("href", "").replace(" ", "").replace("-", "").replace(".", "").lower())
                    or qc in (l.get("text", "").replace(" ", "").replace("-", "").replace(".", "").lower())]
            if hits:
                match_count += len(hits)
                match_details.append(f"Matching links: {len(hits)}")
        except Exception:
            pass

        result_selectors = [
            ".result", ".results", ".search-result", ".search-results", ".card", ".cards",
            ".profile", ".profiles", ".item", ".items", ".entry", ".entries",
            ".record", ".records", ".listing", ".listings", ".match", ".matches", ".found",
            "table tr", ".row", ".data-row", ".info", ".info-card", ".detail",
            "[class*='result']", "[class*='match']", "[class*='found']",
            "[class*='profile']", "[class*='record']",
        ]
        for selector in result_selectors:
            try:
                elements = await page.query_selector_all(selector)
                if elements:
                    has_match = False
                    for el in elements[:50]:
                        text = await el.inner_text()
                        if query.lower() in text.lower():
                            has_match = True
                            break
                    if has_match:
                        match_count += len(elements)
                        match_details.append(f"Selector '{selector}': {len(elements)} elements with match")
                        break
            except Exception:
                pass

        try:
            meta_desc = await page.evaluate(
                """() => document.querySelector('meta[name="description"]')?.content || ''""")
            if query.lower() in meta_desc.lower():
                match_count += 1
                match_details.append("Match in meta description")
        except Exception:
            pass

        status = "success" if match_count > 0 else "no_match"
        return ToolResult(tool_name=tool.name, category=tool.parent_category,
                          url_searched=search_url, status=status,
                          match_count=match_count, match_details=match_details,
                          page_title=page_title)
    except Exception as e:
        return ToolResult(tool_name=tool.name, category=tool.parent_category,
                          url_searched=search_url, status="error", error=str(e)[:200])


# ═══════════════════════════════════════════════════════
# 7. DEEP CRAWL  (unchanged)
# ═══════════════════════════════════════════════════════
async def deep_crawl(page: Page, start_url: str, query: str,
                     max_depth: int = 2, max_pages: int = 30) -> list:
    results = []
    visited = set()
    queue = [(start_url, 0)]
    base_domain = urlparse(start_url).netloc
    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        if urlparse(url).netloc != base_domain:
            continue
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(1500)
            body_text = await page.evaluate("() => document.body.innerText")
            occ = len(re.findall(re.escape(query), body_text, re.IGNORECASE))
            if occ > 0:
                results.append({"url": url, "depth": depth, "matches": occ})
            if depth < max_depth:
                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a'))
                        .map(a => a.href).filter(h => h && h.startsWith('http'))
                """)
                for link in links[:15]:
                    if link not in visited:
                        queue.append((link, depth + 1))
        except Exception:
            continue
    return results


# ═══════════════════════════════════════════════════════
# 8. MULTI-INPUT INTAKE
# ═══════════════════════════════════════════════════════
@dataclass
class InputItem:
    label: str
    value: str
    input_type: InputType


PROMPT_FIELDS = [
    ("name",     InputType.NAME,           "Name"),
    ("email",    InputType.EMAIL,          "Email"),
    ("phone",    InputType.PHONE_US,       "Phone"),
    ("ssn",      InputType.SSN,            "SSN"),
    ("address",  InputType.ADDRESS,        "Address"),
    ("username", InputType.USERNAME,       "Username"),
    ("domain",   InputType.DOMAIN,         "Domain"),
    ("ip",       InputType.IP_ADDRESS,     "IP"),
    ("hash",     InputType.HASH,           "Hash"),
    ("btc",      InputType.BITCOIN_ADDR,   "Bitcoin Address"),
]


def resolve_type(label_type: InputType, value: str) -> InputType:
    """Trust the regex detector when it recognises the value; otherwise fall
    back to the field the user typed it into (e.g. free-form addresses)."""
    detected = detect_input_type(value)
    if detected == InputType.UNKNOWN:
        return label_type
    if label_type in (InputType.PHONE_US, InputType.PHONE_INTL):
        return detected if detected in (InputType.PHONE_US, InputType.PHONE_INTL) else label_type
    return detected


def parse_cli_inputs(argv: list) -> list:
    items = []
    for key, t, label in PROMPT_FIELDS:
        flag = f"--{key}"
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv):
                val = argv[i + 1].strip()
                if val:
                    items.append(InputItem(label, val, resolve_type(t, val)))
    return items


def prompt_inputs() -> list:
    print("Enter values (leave blank to skip):\n")
    items = []
    for key, t, label in PROMPT_FIELDS:
        val = input(f"  {label}: ").strip()
        if val:
            items.append(InputItem(label, val, resolve_type(t, val)))
    return items


# ═══════════════════════════════════════════════════════
# 9. ORCHESTRATOR — one browser session, loop over inputs
# ═══════════════════════════════════════════════════════
@dataclass
class FullOSINTReport:
    input_value: str
    input_type: InputType
    input_label: str = ""
    total_tools_searched: int = 0
    tools_with_matches: int = 0
    total_matches: int = 0
    results: list = field(default_factory=list)
    deep_crawl_results: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


async def search_one_input(page: Page, item: InputItem, all_tools: list,
                           max_tools, delay_between, deep_crawl,
                           idx, total) -> FullOSINTReport:
    log.info(f"\n{'='*70}")
    log.info(f"INPUT {idx}/{total}: {item.label} = '{item.value}'  (type={item.input_type.value})")
    log.info(f"{'='*70}")

    relevant = get_relevant_tools(all_tools, item.input_type)
    if max_tools:
        relevant = relevant[:max_tools]
    log.info(f"Will search {len(relevant)} tools")

    report = FullOSINTReport(input_value=item.value, input_type=item.input_type,
                             input_label=item.label)

    for i, tool in enumerate(relevant, 1):
        log.info(f"[{i}/{len(relevant)}] {tool.name} ({tool.parent_category})")
        result = await analyze_page(page, tool, item.value)
        report.results.append(result)
        report.total_matches += result.match_count
        if result.match_count > 0:
            report.tools_with_matches += 1
            log.info(f"    ✅ {result.match_count} matches — {result.match_details[:3]}")
        else:
            log.info(f"    ❌ {result.status}" + (f" — {result.error}" if result.error else ""))
        report.total_tools_searched += 1
        if i < len(relevant):
            await asyncio.sleep(delay_between)

    if deep_crawl:
        log.info("PHASE 2: Deep crawling pages with matches")
        for result in report.results:
            if result.match_count > 0 and result.status == "success":
                log.info(f"  Deep crawling: {result.tool_name}")
                crs = await deep_crawl(page, result.url_searched, item.value,
                                       max_depth=2, max_pages=20)
                report.deep_crawl_results.extend(crs)
                await asyncio.sleep(1)

    report.summary = {
        "input": item.value,
        "input_label": item.label,
        "input_type": item.input_type.value,
        "tools_searched": report.total_tools_searched,
        "tools_with_matches": report.tools_with_matches,
        "total_matches": report.total_matches,
        "results_by_status": {
            "success": sum(1 for r in report.results if r.status == "success"),
            "no_match": sum(1 for r in report.results if r.status == "no_match"),
            "blocked": sum(1 for r in report.results if r.status == "blocked"),
            "error": sum(1 for r in report.results if r.status == "error"),
        },
    }
    return report


async def run_multi_input_osint(items, deep_crawl=False, headless=True,
                                max_tools=None, delay_between=1.5):
    tree = fetch_osint_tree()
    all_tools = flatten_tree(tree)
    log.info(f"Total tools in OSINT Framework: {len(all_tools)}")

    reports = []
    matches_table = []   # 2D ARRAY: [input, website, matches]

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage",
                  "--disable-blink-features=AutomationControlled", "--disable-extensions"]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
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

        for idx, item in enumerate(items, 1):
            rep = await search_one_input(page, item, all_tools, max_tools,
                                         delay_between, deep_crawl, idx, len(items))
            reports.append(rep)
            # ── build the 2D array: only tools that actually matched ──
            for r in rep.results:
                if r.match_count > 0:
                    matches_table.append([item.value, r.tool_name, r.match_count])

        await browser.close()
    return reports, matches_table


# ═══════════════════════════════════════════════════════
# 10. REPORTING
# ═══════════════════════════════════════════════════════
def print_report(report: FullOSINTReport):
    s = report.summary
    print("\n" + "█" * 75)
    print(f"  INPUT: {report.input_label} = {report.input_value}  (type={s['input_type']})")
    print(f"  Tools searched: {s['tools_searched']} | Tools w/ matches: {s['tools_with_matches']}"
          f" | Total matches: {s['total_matches']}")
    print("  STATUS BREAKDOWN:")
    for status, count in s["results_by_status"].items():
        print(f"    {status:12s}: {count:4d} {'█' * min(count, 40)}")
    print("█" * 75)
    print("  DETAILED RESULTS (tools with matches):")
    for r in sorted(report.results, key=lambda x: -x.match_count):
        if r.match_count > 0:
            print(f"  ✅ {r.tool_name:35s} | {r.match_count:5d} matches")
            print(f"     URL: {r.url_searched[:90]}")


def print_matches_table(matches_table):
    print("\n" + "█" * 75)
    print("  MATCHES — 2D ARRAY  [input, website, matches]")
    print("█" * 75)
    print(json.dumps(matches_table, indent=2))
    print("\n  FORMATTED VIEW:")
    print(f"  {'INPUT':<30} {'WEBSITE':<35} {'MATCHES':>7}")
    print("  " + "─" * 74)
    for row in matches_table:
        print(f"  {row[0][:30]:<30} {row[1][:35]:<35} {row[2]:>7}")
    print("█" * 75)


def export_matches(matches_table, reports):
    with open("osint_matches.json", "w", encoding="utf-8") as f:
        json.dump({
            "matches_table": matches_table,
            "per_input": [
                {
                    "input": r.input_value, "label": r.input_label,
                    "type": r.input_type.value,
                    "tools_searched": r.total_tools_searched,
                    "matches": [
                        {"input": r.input_value, "website": res.tool_name,
                         "matches": res.match_count, "url": res.url_searched}
                        for res in r.results if res.match_count > 0
                    ],
                } for r in reports
            ],
        }, f, indent=2)
    with open("osint_matches.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["input", "website", "matches"])
        w.writerows(matches_table)
    log.info("Saved: osint_matches.json / osint_matches.csv")


# ═══════════════════════════════════════════════════════
# 11. CLI
# ═══════════════════════════════════════════════════════
async def main():
    import sys
    argv = sys.argv[1:]

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║      FULL OSINT FRAMEWORK — MULTI-INPUT AUTOMATED SEARCHER   ║
    ║  name / email / phone / ssn / address / username / domain    ║
    ║  / ip / hash / btc  →  searched per relevant tool  →         ║
    ║  2D array of [input, website, matches]                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    items = parse_cli_inputs(argv)
    if not items:
        items = prompt_inputs()

    if not items:
        print("Error: no inputs provided.")
        return

    deep_crawl = "--deep" in argv
    visible = "--visible" in argv
    limit = None
    for i, arg in enumerate(argv):
        if arg == "--limit" and i + 1 < len(argv):
            limit = int(argv[i + 1])
    delay = 1.5
    for i, arg in enumerate(argv):
        if arg == "--delay" and i + 1 < len(argv):
            delay = float(argv[i + 1])

    reports, matches_table = await run_multi_input_osint(
        items, deep_crawl=deep_crawl, headless=not visible,
        max_tools=limit, delay_between=delay)

    for rep in reports:
        print_report(rep)

    print_matches_table(matches_table)
    export_matches(matches_table, reports)


if __name__ == "__main__":
    asyncio.run(main())