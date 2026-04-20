"""
URL Health Checker — Production-ready Streamlit app.

Usage:
    streamlit run url_health_checker.py

Requirements:
    pip install streamlit pandas requests urllib3
"""

import hashlib
import ipaddress
import logging
import re
import socket
import time
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import streamlit as st

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_INPUT_BYTES      = 1 * 1024 * 1024
MAX_WORKERS          = 10
DEFAULT_TIMEOUT      = 5
MAX_USER_TIMEOUT     = 10
MAX_URLS             = 200
MAX_JOB_SECONDS      = 120
MAX_REDIRECT_DEPTH   = 10
USER_AGENT           = (
    "Mozilla/5.0 (compatible; URLHealthChecker/1.0; "
    "+https://github.com/your-org/url-health-checker)"
)

# No status-based retries — prevents 3x amplification / DDoS relay behaviour.
# One connect retry only, for transient TCP resets.
RETRY_TOTAL          = 1
RETRY_BACKOFF        = 0.3

ALLOWED_EXTENSIONS   = ["txt", "md", "log"]
ALLOWED_PORTS        = {80, 443, 8080, 8443}

_PRIVATE_NETWORKS    = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_FORMULA_CHARS       = ("=", "+", "-", "@", "\t", "\r", "|", "%")


# ---------------------------------------------------------------------------
# Rate limiting — IP-fingerprinted, bounded OrderedDict, OOM-safe
# ---------------------------------------------------------------------------
_MAX_RATE_STORE_ENTRIES = 50_000
_rate_limit_store: OrderedDict = OrderedDict()
_rate_lock           = threading.Lock()
RATE_LIMIT_WINDOW    = 60
RATE_LIMIT_MAX       = 5


def _get_client_fingerprint() -> str:
    """
    Best-effort stable identifier for the connecting client.
    Prefers the real IP from a forwarding header; falls back to the
    Streamlit WebSocket session ID. Hashed so no raw IPs are stored.
    """
    try:
        headers = st.context.headers
        ip = (
            headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or headers.get("X-Real-IP", "")
        )
    except Exception:
        ip = ""

    if not ip:
        try:
            ip = st.runtime.scriptrunner.get_script_run_ctx().session_id
        except Exception:
            ip = "unknown"

    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _check_rate_limit(fingerprint: str) -> bool:
    """
    Sliding-window rate limiter. Evicts stale entries on every call
    to prevent unbounded dict growth. Caps the store as an absolute safety net.
    """
    now          = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    with _rate_lock:
        keys_to_delete = [
            k for k, calls in list(_rate_limit_store.items())
            if not calls or max(calls) <= window_start
        ]
        for k in keys_to_delete:
            del _rate_limit_store[k]

        while len(_rate_limit_store) >= _MAX_RATE_STORE_ENTRIES:
            _rate_limit_store.popitem(last=False)

        calls = [t for t in _rate_limit_store.get(fingerprint, []) if t > window_start]
        if len(calls) >= RATE_LIMIT_MAX:
            return False
        calls.append(now)
        _rate_limit_store[fingerprint] = calls
        _rate_limit_store.move_to_end(fingerprint)

    return True


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------
def _normalize_url(url: str) -> Optional[str]:
    """
    Canonicalize a URL to exactly what requests will fetch.
    Strips fragments, rejects embedded credentials.
    Returns None if the URL is structurally invalid.
    """
    try:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            return None
        return urlunparse(parsed._replace(fragment=""))
    except Exception:
        return None


def _resolve_to_ip_bound_url(url: str) -> tuple:
    """
    Resolve the hostname once, validate every returned IP against the
    private-network blocklist, then rewrite the URL to use the literal
    IP address. This pins the DNS resolution so the IP we validated is
    the IP requests actually connects to — eliminating DNS rebinding / TOCTOU.

    Returns (ip_bound_url, original_hostname, error_reason).
    On success: (url_with_literal_ip, hostname, "")
    On failure: (None, None, reason)
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return None, None, f"Parse error: {exc}"

    if parsed.scheme not in ("http", "https"):
        return None, None, f"Scheme not allowed: {parsed.scheme}"

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        return None, None, f"Port not allowed: {port}"

    hostname = parsed.hostname
    if not hostname:
        return None, None, "No hostname"

    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return None, None, f"DNS resolution failed: {exc}"

    if not infos:
        return None, None, "DNS returned no results"

    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None, None, f"Invalid IP from DNS: {ip_str}"
        for net in _PRIVATE_NETWORKS:
            if ip in net:
                return None, None, f"Private/reserved address: {ip}"

    chosen_ip = infos[0][4][0]
    netloc_ip  = f"[{chosen_ip}]" if ":" in chosen_ip else chosen_ip
    if parsed.port:
        netloc_ip += f":{parsed.port}"

    ip_bound_url = urlunparse(parsed._replace(netloc=netloc_ip))
    return ip_bound_url, hostname, ""


# ---------------------------------------------------------------------------
# URL sanitization helpers
# ---------------------------------------------------------------------------
def _redact_url_for_log(url: str) -> str:
    """Replace query-param values with [REDACTED] before writing to logs."""
    try:
        parsed   = urlparse(url)
        if not parsed.query:
            return url
        params   = parse_qs(parsed.query, keep_blank_values=True)
        redacted = {k: ["[REDACTED]"] for k in params}
        return urlunparse(parsed._replace(query=urlencode(redacted, doseq=True)))
    except Exception:
        return "[URL REDACTED]"


def _sanitize_csv_field(value: object) -> object:
    """Prefix formula-injection chars so spreadsheets treat the cell as text."""
    if isinstance(value, str) and value and value[0] in _FORMULA_CHARS:
        return "'" + value
    return value


def _sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in out.select_dtypes(include="object").columns:
        out[col] = out[col].apply(_sanitize_csv_field)
    return out


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------
@dataclass
class CheckerConfig:
    timeout:          int  = DEFAULT_TIMEOUT
    max_workers:      int  = MAX_WORKERS
    use_head:         bool = True
    follow_redirects: bool = True

    def __post_init__(self) -> None:
        self.timeout     = min(self.timeout, MAX_USER_TIMEOUT)
        self.max_workers = min(self.max_workers, MAX_WORKERS)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
class Extractor:
    def extract(self, text: str) -> list:
        raise NotImplementedError


class URLExtractor(Extractor):
    """Extracts unique, normalized, SSRF-safe http/https URLs from arbitrary text."""

    _PATTERN = re.compile(r'https?://[^\s\[\]"<>{}|\\^`]+')

    def extract(self, text: str) -> list:
        found  = self._PATTERN.findall(text)
        seen   = set()
        unique = []

        for raw in found:
            # Strip trailing punctuation — single pass, not greedy rstrip
            url = re.sub(r'[.,;:)]+$', '', raw)

            url = _normalize_url(url)
            if url is None:
                continue

            if not self._is_valid_format(url):
                continue

            ip_bound, hostname, reason = _resolve_to_ip_bound_url(url)
            if ip_bound is None:
                logger.info("Blocked URL %s — %s", _redact_url_for_log(url), reason)
                continue

            if url not in seen:
                seen.add(url)
                unique.append(url)

        logger.info("Extracted %d safe URL(s).", len(unique))

        if len(unique) > MAX_URLS:
            logger.warning("Clamping URL list from %d to %d.", len(unique), MAX_URLS)
            unique = unique[:MAX_URLS]

        return unique

    @staticmethod
    def _is_valid_format(url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            if not parsed.netloc or "." not in parsed.netloc:
                return False
            return True
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
@dataclass
class URLResult:
    url:              str
    status_code:      Optional[int] = None
    response_time_ms: Optional[int] = None
    final_url:        str           = ""
    error:            str           = ""
    method_used:      str           = ""

    def to_dict(self) -> dict:
        return {
            "url":              self.url,
            "status_code":      self.status_code,
            "response_time_ms": self.response_time_ms,
            "final_url":        self.final_url,
            "error":            self.error,
            "method_used":      self.method_used,
        }


def _make_session(config: CheckerConfig) -> requests.Session:
    """
    Build a requests.Session. Status-based retries are disabled to prevent
    the app being used as a DDoS amplifier (no 3x on 5xx). One connect retry
    only for transient resets.
    """
    session = requests.Session()
    session.max_redirects = MAX_REDIRECT_DEPTH
    session.headers.update({"User-Agent": USER_AGENT})

    retry = Retry(
        total=RETRY_TOTAL,
        connect=1,
        read=0,
        status=0,
        backoff_factor=RETRY_BACKOFF,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session


_thread_local = threading.local()


def _get_session(config: CheckerConfig) -> requests.Session:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = _make_session(config)
    return _thread_local.session


def _clear_session_in_worker() -> None:
    """
    Close and drop this worker thread's session. Must be submitted as a pool
    task — calling from the main thread only clears the main thread's session.
    """
    if hasattr(_thread_local, "session"):
        try:
            _thread_local.session.close()
        except Exception:
            pass
        del _thread_local.session


class URLTester:
    """Tests a single URL and returns a URLResult."""

    def __init__(self, config: CheckerConfig):
        self.config = config

    def test(self, url: str) -> URLResult:
        method = "HEAD" if self.config.use_head else "GET"
        result = self._follow_url(url, method, depth=0)
        if self.config.use_head and (result.error or result.status_code in (405, 501)):
            result = self._follow_url(url, "GET", depth=0)
        return result

    def _follow_url(self, url: str, method: str, depth: int) -> URLResult:
        """
        Depth-tracked entry point for a fetch + redirect chain.
        Re-validates and re-pins the IP on every hop.
        """
        if depth > MAX_REDIRECT_DEPTH:
            return URLResult(url=url, error="Too many redirects", method_used=method)

        ip_bound, hostname, reason = _resolve_to_ip_bound_url(url)
        if ip_bound is None:
            return URLResult(url=url, error=f"Blocked: {reason}", method_used=method)

        session = _get_session(self.config)
        return self._request(session, method, url, ip_bound, hostname, depth)

    def _request(
        self,
        session:   requests.Session,
        method:    str,
        orig_url:  str,
        ip_bound:  str,
        hostname:  str,
        depth:     int,
    ) -> URLResult:
        """
        Single HTTP request using the IP-bound URL with the original Host header.
        Validates and resolves redirect Location values before following them.
        """
        start = time.perf_counter()
        try:
            resp = session.request(
                method,
                ip_bound,
                headers={"Host": hostname},
                timeout=self.config.timeout,
                allow_redirects=False,
                stream=True,
                verify=True,
            )

            if resp.is_redirect and self.config.follow_redirects:
                location = resp.headers.get("Location", "").strip()
                resp.close()

                if not location:
                    return URLResult(
                        url=orig_url,
                        status_code=resp.status_code,
                        error="Redirect with empty Location",
                        method_used=method,
                    )

                # Resolve relative redirects (//host/path, /path) against the
                # original URL before any validation — this is the key fix for
                # the protocol-relative and path-relative SSRF bypass.
                absolute_location = urljoin(orig_url, location)
                absolute_location = _normalize_url(absolute_location)
                if absolute_location is None:
                    return URLResult(
                        url=orig_url,
                        status_code=resp.status_code,
                        error="Redirect URL rejected (credentials or malformed)",
                        method_used=method,
                    )

                return self._follow_url(absolute_location, method, depth + 1)

            resp.close()
            elapsed_ms = round((time.perf_counter() - start) * 1000)
            final      = orig_url if resp.url == ip_bound else ""

            logger.info(
                "%-8s %-60s  %d  (%d ms)",
                method, _redact_url_for_log(orig_url), resp.status_code, elapsed_ms,
            )
            return URLResult(
                url=orig_url,
                status_code=resp.status_code,
                response_time_ms=elapsed_ms,
                final_url=final,
                method_used=method,
            )

        except requests.exceptions.Timeout:
            logger.warning("Timeout [%s]: %s", method, _redact_url_for_log(orig_url))
            return URLResult(url=orig_url, error="Timeout", method_used=method)

        except requests.exceptions.TooManyRedirects:
            logger.warning("Too many redirects [%s]: %s", method, _redact_url_for_log(orig_url))
            return URLResult(url=orig_url, error="Too many redirects", method_used=method)

        except requests.exceptions.SSLError as exc:
            # Never surface the raw exception — it may contain internal hostnames or cert CNs
            err_str = str(exc).lower()
            if "certificate verify failed" in err_str:
                friendly = "SSL: certificate not trusted"
            elif "certificate has expired" in err_str:
                friendly = "SSL: certificate expired"
            elif "hostname" in err_str:
                friendly = "SSL: hostname mismatch"
            else:
                friendly = "SSL handshake failed"
            logger.warning("SSL error [%s] %s: %s", method, _redact_url_for_log(orig_url), exc)
            return URLResult(url=orig_url, error=friendly, method_used=method)

        except requests.exceptions.ConnectionError:
            logger.warning("Connection error [%s]: %s", method, _redact_url_for_log(orig_url))
            return URLResult(url=orig_url, error="Connection error", method_used=method)

        except requests.RequestException as exc:
            logger.warning("Request failed [%s] %s: %s", method, _redact_url_for_log(orig_url), exc)
            return URLResult(url=orig_url, error="Request failed", method_used=method)


# ---------------------------------------------------------------------------
# Health Manager
# ---------------------------------------------------------------------------
class HealthManager:
    """Orchestrates extraction + concurrent testing with a hard time ceiling."""

    def __init__(self, extractor: Extractor, tester: URLTester):
        self.extractor = extractor
        self.tester    = tester

    def run(self, text: str, progress_cb=None) -> tuple:
        urls = self.extractor.extract(text)
        if not urls:
            return [], False

        results    = []
        done_count = 0
        total      = len(urls)
        timed_out  = False
        deadline   = time.monotonic() + MAX_JOB_SECONDS

        max_w = min(self.tester.config.max_workers, total)
        with ThreadPoolExecutor(max_workers=max_w) as pool:
            futures = {pool.submit(self.tester.test, url): url for url in urls}

            for future in as_completed(futures):
                if time.monotonic() > deadline:
                    timed_out = True
                    for f in futures:
                        f.cancel()
                    break

                url = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error("Unexpected error for %s: %s", _redact_url_for_log(url), exc)
                    results.append(URLResult(url=url, error="Unexpected error"))
                finally:
                    done_count += 1
                    if progress_cb:
                        progress_cb(done_count, total)

            # Clean up worker-thread sessions from inside the pool — not from the
            # main thread, which has its own separate _thread_local namespace.
            cleanup = [pool.submit(_clear_session_in_worker) for _ in range(max_w)]
            for f in cleanup:
                try:
                    f.result(timeout=2)
                except Exception:
                    pass

        if timed_out:
            logger.warning(
                "Job hit the %ds ceiling. %d/%d URLs checked.",
                MAX_JOB_SECONDS, len(results), total,
            )

        order = {url: i for i, url in enumerate(urls)}
        results.sort(key=lambda r: order.get(r.url, 9999))
        return results, timed_out


# ---------------------------------------------------------------------------
# Streamlit helpers
# ---------------------------------------------------------------------------
def _status_icon(code: Optional[int]) -> str:
    if code is None:
        return "🔴"
    if 200 <= code < 300:
        return "🟢"
    if 300 <= code < 400:
        return "🟡"
    return "🔴"


def _render_summary(df: pd.DataFrame) -> None:
    total  = len(df)
    ok     = int(df["status_code"].between(200, 299, inclusive="both").sum())
    warns  = int(df["status_code"].between(300, 399, inclusive="both").sum())
    errors = total - ok - warns

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total URLs",   total)
    c2.metric("✅ Healthy",   ok)
    c3.metric("🟡 Redirects", warns)
    c4.metric("❌ Issues",    errors)


def _render_results(df: pd.DataFrame) -> None:
    _render_summary(df)

    display_df = df.copy()
    display_df.insert(0, "health", display_df["status_code"].apply(_status_icon))
    display_df.rename(
        columns={
            "health":           " ",
            "url":              "URL",
            "status_code":      "Status",
            "response_time_ms": "Response (ms)",
            "final_url":        "Final URL (redirect)",
            "error":            "Error",
            "method_used":      "Method",
        },
        inplace=True,
    )
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    safe_df   = _sanitize_dataframe(df)
    csv_bytes = safe_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Export as CSV",
        data=csv_bytes,
        file_name="url_health_results.csv",
        mime="text/csv",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    st.set_page_config(
        page_title="URL Health Checker",
        page_icon="🔗",
        layout="wide",
    )
    st.title("🔗 URL Health Checker")
    st.caption("Extract, test, and monitor URLs from any text or file.")

    # Build the sidebar before the run-gate so the UI renders on all reruns
    with st.sidebar:
        st.header("⚙️ Settings")
        timeout = st.slider(
            "Request timeout (seconds)", min_value=1, max_value=MAX_USER_TIMEOUT,
            value=DEFAULT_TIMEOUT,
        )
        max_workers = st.slider(
            "Concurrent workers", min_value=1, max_value=MAX_WORKERS,
            value=5,
            help="Higher = faster, but be polite to servers.",
        )
        use_head = st.toggle(
            "Use HEAD requests first",
            value=True,
            help="Faster and lower-bandwidth. Falls back to GET automatically.",
        )
        follow_redirects = st.toggle("Follow redirects", value=True)

        st.divider()
        st.header("📥 Input")
        mode = st.radio("Input mode", ("Paste Text", "Upload File"), horizontal=True)

        input_text = ""
        if mode == "Paste Text":
            input_text = st.text_area("Paste your text here", height=220)
        else:
            uploaded = st.file_uploader(
                "Upload a plain-text file",
                type=ALLOWED_EXTENSIONS,
                help="Accepted: .txt, .md, .log",
            )
            if uploaded is not None:
                uploaded.seek(0, 2)
                file_size = uploaded.tell()
                uploaded.seek(0)

                if file_size > MAX_INPUT_BYTES:
                    st.error(
                        f"File too large ({file_size // 1024} KB). "
                        f"Maximum is {MAX_INPUT_BYTES // 1024} KB."
                    )
                    return

                try:
                    input_text = uploaded.read().decode("utf-8")
                except UnicodeDecodeError:
                    st.error("Could not decode file. Please upload a UTF-8 encoded text file.")
                    return

        run = st.button("🚀 Run Check", type="primary", use_container_width=True)

    if "results_df" not in st.session_state:
        st.session_state["results_df"] = None

    if not run:
        if st.session_state["results_df"] is not None:
            st.subheader("Previous Results")
            _render_results(st.session_state["results_df"])
        else:
            st.info("Configure your input in the sidebar, then click **Run Check**.")
        return

    # Rate limit check — inside the run gate so slider moves don't burn quota
    fp = _get_client_fingerprint()
    if not _check_rate_limit(fp):
        # Generic message — never reveal the exact window size or limit to the client
        st.error("Too many requests. Please wait before running another check.")
        return

    if not input_text.strip():
        st.warning("Please provide some text or upload a file first.")
        return

    config    = CheckerConfig(
        timeout=timeout,
        max_workers=max_workers,
        use_head=use_head,
        follow_redirects=follow_redirects,
    )
    extractor = URLExtractor()
    tester    = URLTester(config)
    manager   = HealthManager(extractor, tester)

    urls = extractor.extract(input_text)
    if not urls:
        st.warning("No valid public URLs found. Private/reserved addresses are blocked.")
        return

    st.info(f"Found **{len(urls)}** URL(s). Testing now… (max {MAX_JOB_SECONDS}s)")

    progress_bar = st.progress(0.0)
    status_text  = st.empty()

    def on_progress(done: int, total: int) -> None:
        progress_bar.progress(done / total)
        status_text.text(f"Checked {done} / {total} URLs…")

    results, timed_out = manager.run(input_text, progress_cb=on_progress)

    progress_bar.empty()
    status_text.empty()

    if timed_out:
        st.warning(
            f"Job hit the {MAX_JOB_SECONDS}s time limit. "
            f"Showing {len(results)} of {len(urls)} URLs checked."
        )

    if not results:
        st.warning("No results returned.")
        return

    df = pd.DataFrame([r.to_dict() for r in results])
    st.session_state["results_df"] = df

    st.subheader("Results")
    _render_results(df)


if __name__ == "__main__":
    main()
