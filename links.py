#!/usr/bin/env python3
"""
discover_endpoints.py

Discover hidden endpoints, parameters, and JavaScript files of a target web application.

Usage: run python discover_endpoints.py and follow prompts.

Only use against targets you own or have explicit permission to test.

Dependencies:
    pip install requests beautifulsoup4 tldextract
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Set, List, Tuple, Optional
import json
import re
import sys
import time
import urllib.parse

import requests
from bs4 import BeautifulSoup  # HTML parsing
import tldextract

# ----------------------- Configuration & Regex -----------------------
USER_AGENT = "Mozilla/5.0 (compatible; discover_endpoints/1.0; +https://example.local/)"
REQUEST_TIMEOUT = 12
MAX_WORKERS = 20
RATE_LIMIT_SECONDS = 0.2  # small polite delay between requests in path bruteforce

# Useful regexes for discovery inside JS/text
RE_URL_LIKE = re.compile(
    r"""(?P<url>(?:https?:\/\/[^\s"']+)|(?:\/[a-z0-9_\-./]{2,200})|(?:[a-z0-9_\-./]{2,200}\.(?:php|asp|aspx|json|html|jsp|xml)))""",
    re.I
)
RE_PARAM_ASSIGN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_-]{1,50})\s*[:=]\s*(?:'|\")?([A-Za-z0-9_\-\/\.@]{1,200})(?:'|\")?")
RE_QUERY_PARAM = re.compile(r"[?&]([A-Za-z0-9_\-]{1,50})=")
RE_XHR_FETCH = re.compile(r"\b(fetch|axios|XMLHttpRequest|open|post|get)\b", re.I)
RE_POSSIBLE_KEY = re.compile(r"(?i)(api_key|apikey|token|secret|access_token|client_secret)[:= \t'\"]+([A-Za-z0-9\-_\.]{8,200})")

# ----------------------- Helpers -----------------------
def now_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def normalize_url(base: str, url: str) -> Optional[str]:
    """
    Make a full absolute URL from base and a (possibly relative) url.
    Returns None if the produced URL is invalid or not http(s).
    """
    if not url:
        return None
    url = url.strip().strip('\'"')
    try:
        joined = urllib.parse.urljoin(base, url)
        parsed = urllib.parse.urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        # remove fragments
        cleaned = parsed._replace(fragment="").geturl()
        # strip trailing slash normalization (keep single slash)
        return cleaned.rstrip("/")
    except Exception:
        return None

def get_domain_host(url: str) -> Tuple[str, str]:
    """
    Return (registered_domain, host) for a URL. e.g. ("example.com", "api.sub.example.com")
    """
    p = urllib.parse.urlparse(url)
    host = p.netloc.lower()
    ex = tldextract.extract(host)
    domain = ".".join([part for part in (ex.domain, ex.suffix) if part])
    return domain, host

def safe_request_get(url: str, session: requests.Session, allow_redirects=True, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    """
    GET request with basic error handling and UA.
    We don't verify certs by default but we'll keep verify=True unless user opts otherwise.
    """
    try:
        r = session.get(url, timeout=timeout, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None

# ----------------------- Core discovery functions -----------------------
def fetch_page(url: str, session: requests.Session, verify_tls: bool=True) -> Tuple[Optional[str], Optional[requests.Response]]:
    """
    Fetch HTML/text from a URL. Returns (text, response-object) or (None,None) on failure.
    """
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=verify_tls)
        if r.status_code >= 400:
            # still return body sometimes (404 pages may contain useful JS/links)
            return r.text, r
        return r.text, r
    except Exception:
        return None, None

def parse_html_for_assets(base_url: str, html: str) -> Dict[str, Set[str]]:
    """
    Parse HTML and return dict with:
      - links: href anchors
      - forms: (action URLs) and input names
      - scripts: src links and inline script blocks
      - meta: meta tags (possibly api endpoints)
    """
    links = set()
    forms = set()
    form_params = set()
    scripts = set()
    inline_scripts = []
    metas = set()

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        # fallback naive scanning
        for m in RE_URL_LIKE.finditer(html or ""):
            s = m.group("url")
            u = normalize_url(base_url, s)
            if u:
                links.add(u)
        return {"links": links, "forms": forms, "form_params": form_params, "scripts": scripts, "inline_scripts": inline_scripts, "meta": metas}

    # anchors
    for a in soup.find_all("a", href=True):
        u = normalize_url(base_url, a["href"])
        if u:
            links.add(u)
    # forms
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        ua = normalize_url(base_url, action) or base_url  # action may be relative or empty -> current page
        forms.add(ua)
        # inputs
        for inp in f.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                form_params.add(name.strip())
    # scripts
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            u = normalize_url(base_url, src)
            if u:
                scripts.add(u)
        else:
            # inline script content
            content = (s.string or "") or ""
            if content.strip():
                inline_scripts.append(content)
    # meta tags
    for m in soup.find_all("meta"):
        if m.get("content"):
            metas.add(m.get("content").strip())
        if m.get("name"):
            metas.add(m.get("name").strip())
    return {"links": links, "forms": forms, "form_params": form_params, "scripts": scripts, "inline_scripts": inline_scripts, "meta": metas}

def find_urls_and_params_in_text(text: str, domain_host: str = "") -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """
    Scan a text blob (JS or HTML) for:
      - url-like strings (absolute or path-like)
      - named parameters / query params
      - possible keys/tokens
      - XHR/fetch occurrences
    Returns (urls, param_names, tokens, xhr_strings)
    """
    found_urls = set()
    params = set()
    tokens = set()
    xhrs = set()

    for m in RE_URL_LIKE.finditer(text or ""):
        val = m.group("url")
        # normalize relative url-like if starts with '/'
        if val.startswith("/"):
            # leave as path (we'll join later with base)
            found_urls.add(val)
        elif val.lower().startswith("http"):
            found_urls.add(val.split("#",1)[0].rstrip("/"))
        else:
            # filename-like or path-like
            found_urls.add(val)

    for m in RE_QUERY_PARAM.finditer(text or ""):
        params.add(m.group(1))

    for m in RE_PARAM_ASSIGN.finditer(text or ""):
        params.add(m.group(1))

    for m in RE_POSSIBLE_KEY.finditer(text or ""):
        tokens.add(m.group(0))

    for m in RE_XHR_FETCH.finditer(text or ""):
        xhrs.add(m.group(0))

    # Filter suspiciously long absolute URLs (keep) and eliminate non-http scheme weirdness
    return found_urls, params, tokens, xhrs

def fetch_and_scan_js(js_url: str, base_page: str, session: requests.Session, verify_tls: bool=True) -> Dict:
    """
    Download a JS file and scan it for URLs/params/tokens. Returns a dict with findings.
    """
    res = {"js_url": js_url, "status": None, "urls": set(), "params": set(), "tokens": set(), "xhrs": set()}
    try:
        r = session.get(js_url, timeout=REQUEST_TIMEOUT, verify=verify_tls)
        res["status"] = getattr(r, "status_code", None)
        text = r.text or ""
        urls, params, tokens, xhrs = find_urls_and_params_in_text(text, domain_host=base_page)
        # Normalize URLs: join relative ones with base_page
        normalized = set()
        for u in urls:
            n = normalize_url(js_url, u) or (u if u.startswith("/") else None)
            if n:
                normalized.add(n)
            else:
                normalized.add(u)
        res["urls"] = normalized
        res["params"] = params
        res["tokens"] = tokens
        res["xhrs"] = xhrs
    except Exception as e:
        res["error"] = str(e)
    return res

# ----------------------- Crawl & orchestrate -----------------------
class Discoverer:
    def __init__(self, base_url: str, verify_tls: bool=True, max_depth: int=2, follow_external: bool=False, scan_js: bool=True):
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.max_depth = max_depth
        self.follow_external = follow_external
        self.scan_js = scan_js
        self.parsed_base = urllib.parse.urlparse(self.base_url)
        self.base_domain, self.base_host = get_domain_host(self.base_url)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.discovered_urls: Set[str] = set()
        self.discovered_paths: Set[str] = set()
        self.discovered_params: Set[str] = set()
        self.discovered_js: Set[str] = set()
        self.js_findings: Dict[str, Dict] = {}
        self.discovered_tokens: Set[str] = set()
        self.discovered_xhr_signals: Set[str] = set()
        self.robots_paths: Set[str] = set()
        self.sitemap_paths: Set[str] = set()

    def fetch_robots(self):
        robots_url = urllib.parse.urljoin(self.base_url, "/robots.txt")
        try:
            r = self.session.get(robots_url, timeout=REQUEST_TIMEOUT, verify=self.verify_tls)
            if r and r.status_code == 200 and r.text:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("disallow:"):
                        path = line.split(":",1)[1].strip()
                        if path:
                            # make absolute URL
                            u = normalize_url(self.base_url, path)
                            if u:
                                self.robots_paths.add(u)
                            else:
                                self.robots_paths.add(path)
        except Exception:
            pass

    def fetch_sitemap(self):
        # common sitemap locations
        sm_urls = [urllib.parse.urljoin(self.base_url, "/sitemap.xml"), urllib.parse.urljoin(self.base_url, "/sitemap_index.xml")]
        for sm in sm_urls:
            try:
                r = self.session.get(sm, timeout=REQUEST_TIMEOUT, verify=self.verify_tls)
                if r and r.status_code == 200 and r.text:
                    # crude extract of urls
                    for m in re.finditer(r"<loc>([^<]+)</loc>", r.text, re.I):
                        loc = m.group(1).strip()
                        self.sitemap_paths.add(loc)
            except Exception:
                continue

    def crawl(self):
        """
        BFS crawl limited by depth; collects links, forms, scripts, inline scripts, etc.
        """
        to_visit = [(self.base_url, 0)]
        visited = set()
        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            # respect depth
            if depth > self.max_depth:
                continue
            text, resp = fetch_page(url, self.session, verify_tls=self.verify_tls)
            if text is None:
                continue
            self.discovered_urls.add(url)
            parsed = urllib.parse.urlparse(url)
            # parse HTML for assets
            assets = parse_html_for_assets(url, text)
            # add links
            for link in assets["links"]:
                ld = urllib.parse.urlparse(link)
                # check domain
                if ld.netloc:
                    try:
                        domain, host = get_domain_host(link)
                    except Exception:
                        domain = ""
                        host = ld.netloc
                    same_domain = (domain == self.base_domain) or (host.endswith(self.base_domain))
                    if same_domain:
                        if link not in visited:
                            to_visit.append((link, depth + 1))
                    else:
                        if self.follow_external:
                            if link not in visited:
                                to_visit.append((link, depth + 1))
                        # don't follow external by default
                else:
                    # relative link becomes absolute
                    if link not in visited:
                        to_visit.append((link, depth + 1))
                # record the path
                path_only = urllib.parse.urlparse(link).path
                if path_only:
                    self.discovered_paths.add(path_only)
            # forms and params
            for f in assets["forms"]:
                self.discovered_paths.add(urllib.parse.urlparse(f).path or f)
            for p in assets["form_params"]:
                self.discovered_params.add(p)
            # inline scripts scan
            for script_text in assets["inline_scripts"]:
                urls, params, tokens, xhrs = find_urls_and_params_in_text(script_text)
                for u in urls:
                    # store raw path or url - normalization later
                    self.discovered_paths.add(u)
                for p in params:
                    self.discovered_params.add(p)
                for t in tokens:
                    self.discovered_tokens.add(t)
                for x in xhrs:
                    self.discovered_xhr_signals.add(x)
            # external scripts
            for s in assets["scripts"]:
                self.discovered_js.add(s)
            # meta hints
            for m in assets["meta"]:
                urls, params, tokens, xhrs = find_urls_and_params_in_text(m)
                for u in urls:
                    self.discovered_paths.add(u)
                for p in params:
                    self.discovered_params.add(p)
        # done crawl

    def scan_js_files(self):
        """
        Download & scan each external JS file concurrently.
        """
        if not self.discovered_js:
            return
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(self.discovered_js))) as exe:
            futures = {exe.submit(fetch_and_scan_js, js_url, self.base_url, self.session, self.verify_tls): js_url for js_url in self.discovered_js}
            for fut in as_completed(futures):
                js_url = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"js_url": js_url, "error": str(e)}
                # store findings
                self.js_findings[js_url] = {
                    "status": res.get("status"),
                    "urls": sorted(list(res.get("urls", []))),
                    "params": sorted(list(res.get("params", []))),
                    "tokens": sorted(list(res.get("tokens", []))),
                    "xhrs": sorted(list(res.get("xhrs", []))),
                    "error": res.get("error")
                }
                # merge into global sets
                for u in res.get("urls", []) or []:
                    self.discovered_paths.add(u)
                for p in res.get("params", []) or []:
                    self.discovered_params.add(p)
                for t in res.get("tokens", []) or []:
                    self.discovered_tokens.add(t)
                for x in res.get("xhrs", []) or []:
                    self.discovered_xhr_signals.add(x)

    def run_wordlist_bruteforce(self, wordlist_path: Path, extra_extensions: List[str], threads: int=10, rate: float=RATE_LIMIT_SECONDS):
        """
        Brute-forces path names by appending wordlist entries to base_url and checking HTTP response codes.
        Only records found paths (status < 400).
        """
        if not wordlist_path.exists():
            print(f"[!] Wordlist not found: {wordlist_path}")
            return
        try:
            lines = [l.strip() for l in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")]
        except Exception as e:
            print(f"[!] Could not read wordlist: {e}")
            return
        checks = []
        for token in lines:
            # token may be a path like admin or admin.php - generate variants
            token = token.lstrip("/")
            checks.append(token)
            for ext in extra_extensions:
                if not token.endswith(ext):
                    checks.append(f"{token}{ext}")
        # Deduplicate
        checks = list(dict.fromkeys(checks))
        print(f"[*] Bruteforce checking {len(checks)} paths (polite). This may take time.")
        found = set()
        with ThreadPoolExecutor(max_workers=threads) as exe:
            futures = {}
            for c in checks:
                candidate = urllib.parse.urljoin(self.base_url + "/", c)
                futures[exe.submit(self._probe_path, candidate)] = candidate
                time.sleep(rate)  # polite pacing
            for fut in as_completed(futures):
                candidate = futures[fut]
                try:
                    status = fut.result()
                except Exception:
                    status = None
                if status and status < 400:
                    p = urllib.parse.urlparse(candidate).path
                    self.discovered_paths.add(p)
                    found.add((candidate, status))
        print(f"[*] Bruteforce found {len(found)} live-ish paths (status < 400).")
        return sorted(found, key=lambda x: x[0])

    def _probe_path(self, url: str) -> Optional[int]:
        try:
            r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=self.verify_tls)
            return getattr(r, "status_code", None)
        except Exception:
            return None

    def summarise(self) -> Dict:
        """
        Return a structured summary dictionary of all discoveries.
        """
        return {
            "base_url": self.base_url,
            "base_domain": self.base_domain,
            "discovered_urls": sorted(list(self.discovered_urls)),
            "discovered_paths": sorted(list(self.discovered_paths)),
            "discovered_params": sorted(list(self.discovered_params)),
            "discovered_js": sorted(list(self.discovered_js)),
            "js_findings": self.js_findings,
            "discovered_tokens": sorted(list(self.discovered_tokens)),
            "discovered_xhr_signals": sorted(list(self.discovered_xhr_signals)),
            "robots_paths": sorted(list(self.robots_paths)),
            "sitemap_paths": sorted(list(self.sitemap_paths))
        }

# ----------------------- CLI Interaction & Save -----------------------
def save_output(outdir: Path, summary: Dict):
    outdir.mkdir(parents=True, exist_ok=True)
    ts = now_ts()
    jsonp = outdir / f"discovery_{ts}.json"
    txtp = outdir / f"discovery_{ts}.txt"
    with jsonp.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    # human-friendly text
    with txtp.open("w", encoding="utf-8") as f:
        f.write(f"Discovery of {summary.get('base_url')}\nGenerated: {ts}\n\n")
        f.write("Robots disallowed paths:\n")
        for p in summary.get("robots_paths", []):
            f.write(f"  {p}\n")
        f.write("\nSitemap paths:\n")
        for p in summary.get("sitemap_paths", []):
            f.write(f"  {p}\n")
        f.write("\nDiscovered paths / endpoints:\n")
        for p in summary.get("discovered_paths", []):
            f.write(f"  {p}\n")
        f.write("\nDiscovered parameter names:\n")
        for p in summary.get("discovered_params", []):
            f.write(f"  {p}\n")
        f.write("\nDiscovered JS files and findings:\n")
        for js, info in summary.get("js_findings", {}).items():
            f.write(f"JS: {js}\n")
            if info.get("error"):
                f.write(f"   Error: {info.get('error')}\n")
                continue
            if info.get("urls"):
                f.write("   URLs:\n")
                for u in info.get("urls", []):
                    f.write(f"     {u}\n")
            if info.get("params"):
                f.write("   Params:\n")
                for pt in info.get("params", []):
                    f.write(f"     {pt}\n")
            if info.get("tokens"):
                f.write("   Tokens (possible API keys/tokens -- review carefully):\n")
                for tk in info.get("tokens", []):
                    f.write(f"     {tk}\n")
            if info.get("xhrs"):
                f.write("   XHR/fetch tokens:\n")
                for x in info.get("xhrs", []):
                    f.write(f"     {x}\n")
            f.write("\n")
    print(f"Saved JSON -> {jsonp}\nSaved text -> {txtp}")

def main_cli():
    print("=== Hidden Endpoint & JS Discovery Tool ===")
    print("Only use against targets you own or have permission to test.\n")
    target = input("Target URL (e.g. https://example.com): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return
    # normalize url
    if not urllib.parse.urlparse(target).scheme:
        target = "https://" + target
    max_depth = int(input("Crawl max depth (default 2): ").strip() or "2")
    follow_external = input("Follow external links? (y/N): ").strip().lower() == "y"
    scan_js = input("Download & scan external JS files? (Y/n): ").strip().lower() != "n"
    bruteforce = input("Run path bruteforce from wordlist? (y/N): ").strip().lower() == "y"
    wordlist_path = None
    if bruteforce:
        path_in = input("Path to wordlist (one token per line) [common wordlists recommended]: ").strip()
        wordlist_path = Path(path_in)
    extensions_raw = input("Extra extensions to try in bruteforce (comma separated, default: .php,.asp,.aspx,.json): ").strip() or ".php,.asp,.aspx,.json"
    extra_exts = [e.strip() for e in extensions_raw.split(",") if e.strip()]
    verify_tls = input("Verify TLS certificates? (y/N) - set to N to ignore cert warnings: ").strip().lower() == "y"

    discoverer = Discoverer(target, verify_tls=verify_tls, max_depth=max_depth, follow_external=follow_external, scan_js=scan_js)

    print("\n[*] Fetching robots.txt and sitemap.xml (if available)...")
    discoverer.fetch_robots()
    discoverer.fetch_sitemap()
    print(f"  robots disallowed: {len(discoverer.robots_paths)} entries, sitemap: {len(discoverer.sitemap_paths)} found.")

    print("\n[*] Starting crawl...")
    discoverer.crawl()
    print(f"  crawl complete. pages found: {len(discoverer.discovered_urls)} links found: {len(discoverer.discovered_paths)} js files: {len(discoverer.discovered_js)}")

    if scan_js and discoverer.discovered_js:
        print("\n[*] Scanning external JS files (this may take a while)...")
        discoverer.scan_js_files()
        print(f"  scanned js files: {len(discoverer.js_findings)}")

    if bruteforce and wordlist_path:
        print("\n[*] Running wordlist bruteforce (polite) ...")
        bf_found = discoverer.run_wordlist_bruteforce(wordlist_path, extra_exts, threads=10)
        if bf_found:
            print("Bruteforce discovered:")
            for u, sc in bf_found[:40]:
                print(f"  {u} - {sc}")

    summary = discoverer.summarise()

    # Optionally, post-process discovered_paths to convert relative paths to full URLs (base)
    normalized_full_urls = set()
    for p in summary.get("discovered_paths", []):
        # if p already looks like full URL, keep
        if p.lower().startswith("http"):
            normalized_full_urls.add(p)
        elif p.startswith("/"):
            normalized_full_urls.add(urllib.parse.urljoin(discoverer.base_url, p.lstrip("/")))
        else:
            # could be path-like or filename -> join
            normalized_full_urls.add(urllib.parse.urljoin(discoverer.base_url + "/", p))
    summary["discovered_full_urls"] = sorted(normalized_full_urls)

    print("\n[*] Summary:")
    print(f" Base URL: {summary.get('base_url')}")
    print(f" Discovered JS files: {len(summary.get('discovered_js'))}")
    print(f" Discovered endpoints/paths: {len(summary.get('discovered_paths'))}")
    print(f" Discovered params: {len(summary.get('discovered_params'))}")
    print(f" Possible tokens found in JS: {len(summary.get('discovered_tokens'))}")

    # show a brief sample of interesting findings
    sample_paths = summary.get("discovered_full_urls", [])[:30]
    if sample_paths:
        print("\nSample discovered endpoints:")
        for s in sample_paths[:30]:
            print("  " + s)

    save = input("\nSave results to disk? (Y/n): ").strip().lower() != "n"
    if save:
        outdir = Path(f"discovery_results_{now_ts()}")
        save_output(outdir, summary)
    else:
        print("Skipping save.")

    print("\nDone. Review the output files and manually verify any sensitive strings before acting on them.")

if __name__ == "__main__":
    try:
        main_cli()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(1)
