"""
URL Health Checker — Production-ready Streamlit app.

Usage:
    streamlit run url_health_checker.py

Requirements:
    pip install streamlit pandas requests urllib3
"""

import ipaddress
import logging
import re
import signal
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

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
MAX_INPUT_BYTES     = 1 * 1024 * 1024   # 1 MB guard
MAX_WORKERS         = 10                # conservative
DEFAULT_TIMEOUT     = 5                 # seconds
MAX_USER_TIMEOUT    = 10                # hard ceiling users can't override
MAX_URLS            = 200               # tighter cap (was 500)
MAX_JOB_SECONDS     = 120              # hard wall on total job time
USER_AGENT          = (
    "Mozilla/5.0 (compatible; URLHealthChecker/1.0; "
    "+https://github.com/your-org/url-health-checker)"
)
RETRY_TOTAL         = 2
RETRY_BACKOFF       = 0.3
RETRY_STATUS_CODES  = (429, 500, 502, 503, 504)

# Allowed file types — plain text only; no XML/JSON/HTML parsing
ALLOWED_EXTENSIONS  = ["txt", "md", "log"]

# Ports we are willing to connect to on external hosts
ALLOWED_PORTS       = {80, 443, 8080, 8443}

# RFC-1918 and other private / link-local / loopback ranges
_PRIVATE_NETWORKS   = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/GCP/Azure metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Characters that make a CSV field a formula in Excel / LibreOffice
_FORMULA_CHARS      = ("=", "+", "-", "@", "\t", "\r", "|", "%")

# ---------------------------------------------------------------------------
# Rate limiting (simple token bucket, per-session)
# ---------------------------------------------------------------------------
_rate_limit_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()
RATE_LIMIT_WINDOW   = 60   # seconds
RATE_LIMIT_MAX      = 5    # runs per window per session


def _check_rate_limit(session_id: str) -> bool:
    """Return False if the session has exceeded the allowed request rate."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    with _rate_lock:
        calls = [t for t in _rate_limit_store.get(session_id, []) if t > window_start]
        if len(calls) >= RATE_LIMIT_MAX:
            return False
        calls.append(now)
        _rate_limit_store[session_id] = calls
    return True


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------
def _is_safe_url(url: str) -> tuple[bool, str]:
    """
    Return (True, "") if the URL is safe to fetch.
    Return (False, reason) if it should be blocked.

    Checks:
      - Scheme must be http or https
      - Port must be in ALLOWED_PORTS
      - Resolved IP must not be in any private/reserved range
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return False, f"Parse error: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme not allowed: {parsed.scheme}"

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        return False, f"Port not allowed: {port}"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname"

    try:
        # Resolve hostname → check every returned address
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return False, f"DNS resolution failed: {exc}"

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP: {ip_str}"
        for net in _PRIVATE_NETWORKS:
            if ip in net:
                return False, f"Private/reserved address: {ip}"

    return True, ""


# ---------------------------------------------------------------------------
# URL sanitization helpers
# ---------------------------------------------------------------------------
def _redact_url_for_log(url: str) -> str:
    """Strip query-param values before writing a URL to logs."""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        params = parse_qs(parsed.query, keep_blank_values=True)
        redacted = {k: ["[REDACTED]"] for k in params}
        return urlunparse(parsed._replace(query=urlencode(redacted, doseq=True)))
    except Exception:
        return "[URL REDACTED]"


def _sanitize_csv_field(value: object) -> object:
    """Prefix formula-injection characters so spreadsheet apps treat them as text."""
    if isinstance(value, str) and value and value[0] in _FORMULA_CHARS:
        return "'" + value
    return value


def _sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply CSV formula injection sanitization to all string columns."""
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
        # Enforce server-side ceilings regardless of what the UI sends
        self.timeout     = min(self.timeout, MAX_USER_TIMEOUT)
        self.max_workers = min(self.max_workers, MAX_WORKERS)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
class Extractor:
    def extract(self, text: str) -> list[str]:
        raise NotImplementedError


class URLExtractor(Extractor):
    """Extracts unique, validated, SSRF-safe http/https URLs from arbitrary text."""

    _PATTERN = re.compile(r'https?://[^\s\[\]"<>{}|\\^`]+')

    def extract(self, text: str) -> list[str]:
        found = self._PATTERN.findall(text)
        seen:   set[str]  = set()
        unique: list[str] = []

        for raw in found:
            url = raw.rstrip(".,;:)")
            if not self._is_valid_format(url):
                continue
            safe, reason = _is_safe_url(url)
            if not safe:
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
    """Return a requests.Session with retry logic and safe defaults."""
    session = requests.Session()
    session.max_redirects = 10
    session.headers.update({"User-Agent": USER_AGENT})

    retry = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=RETRY_STATUS_CODES,
        allowed_methods={"HEAD", "GET"},
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


def _clear_thread_sessions() -> None:
    """Close and drop the thread-local session to prevent state bleed between jobs."""
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
        session = _get_session(self.config)
        if self.config.use_head:
            result = self._request(session, "HEAD", url)
            if result.error or result.status_code in (405, 501):
                result = self._request(session, "GET", url)
        else:
            result = self._request(session, "GET", url)
        return result

    def _request(self, session: requests.Session, method: str, url: str) -> URLResult:
        start = time.perf_counter()
        try:
            # Fetch without auto-redirect so we can validate the destination first
            resp = session.request(
                method,
                url,
                timeout=self.config.timeout,
                allow_redirects=False,
                stream=True,
            )

            # Validate redirect destination before following
            if resp.is_redirect and self.config.follow_redirects:
                location = resp.headers.get("Location", "")
                if location:
                    safe, reason = _is_safe_url(location)
                    if not safe:
                        logger.warning(
                            "Redirect blocked for %s: %s",
                            _redact_url_for_log(url), reason,
                        )
                        resp.close()
                        return URLResult(
                            url=url,
                            status_code=resp.status_code,
                            error="Redirect to private/disallowed host blocked",
                            method_used=method,
                        )
                    resp.close()
                    # Follow the safe redirect
                    return self._request(session, method, location)

            resp.close()
            elapsed_ms = round((time.perf_counter() - start) * 1000)
            final = resp.url if resp.url != url else ""

            logger.info(
                "%-8s %-60s  %d  (%d ms)",
                method, _redact_url_for_log(url), resp.status_code, elapsed_ms,
            )
            return URLResult(
                url=url,
                status_code=resp.status_code,
                response_time_ms=elapsed_ms,
                final_url=final,
                method_used=method,
            )

        except requests.exceptions.Timeout:
            logger.warning("Timeout [%s]: %s", method, _redact_url_for_log(url))
            return URLResult(url=url, error="Timeout", method_used=method)

        except requests.exceptions.TooManyRedirects:
            logger.warning("Too many redirects [%s]: %s", method, _redact_url_for_log(url))
            return URLResult(url=url, error="Too many redirects", method_used=method)

        except requests.exceptions.SSLError as exc:
            err_str = str(exc).lower()
            if "certificate verify failed" in err_str:
                friendly = "SSL: certificate not trusted (possible MITM or self-signed cert)"
            elif "certificate has expired" in err_str:
                friendly = "SSL: certificate expired"
            elif "hostname" in err_str:
                friendly = "SSL: hostname mismatch (possible MITM)"
            else:
                friendly = "SSL error (see server logs for details)"
            logger.warning("SSL error [%s]: %s", method, _redact_url_for_log(url))
            return URLResult(url=url, error=friendly, method_used=method)

        except requests.exceptions.ConnectionError:
            logger.warning("Connection error [%s]: %s", method, _redact_url_for_log(url))
            return URLResult(url=url, error="Connection error", method_used=method)

        except requests.RequestException as exc:
            logger.warning("Request failed [%s] %s", method, _redact_url_for_log(url))
            return URLResult(url=url, error=str(exc), method_used=method)


# ---------------------------------------------------------------------------
# Health Manager
# ---------------------------------------------------------------------------
class HealthManager:
    """Orchestrates extraction + concurrent testing with a hard time ceiling."""

    def __init__(self, extractor: Extractor, tester: URLTester):
        self.extractor = extractor
        self.tester    = tester

    def run(
        self,
        text:        str,
        progress_cb  = None,
    ) -> list[URLResult]:
        urls = self.extractor.extract(text)
        if not urls:
            return []

        results:    list[URLResult] = []
        done_count  = 0
        total       = len(urls)
        timed_out   = False

        # Hard wall: cancel remaining futures if the job exceeds MAX_JOB_SECONDS
        deadline = time.monotonic() + MAX_JOB_SECONDS

        max_w = min(self.tester.config.max_workers, total)
        with ThreadPoolExecutor(max_workers=max_w) as pool:
            futures = {pool.submit(self.tester.test, url): url for url in urls}
            for future in as_completed(futures):
                if time.monotonic() > deadline:
                    timed_out = True
                    # Cancel remaining futures (best-effort)
                    for f in futures:
                        f.cancel()
                    break

                url = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error("Unexpected error for %s: %s", _redact_url_for_log(url), exc)
                    results.append(URLResult(url=url, error=f"Unexpected: {exc}"))
                finally:
                    done_count += 1
                    if progress_cb:
                        progress_cb(done_count, total)

        # Clean up thread-local sessions after each job run to prevent state bleed
        _clear_thread_sessions()

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

    # Sanitize CSV export to prevent formula injection
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

    # ---- Rate limiting (keyed by Streamlit session ID) ----
    session_id = st.runtime.scriptrunner.get_script_run_ctx().session_id
    if not _check_rate_limit(session_id):
        st.error(
            f"Too many requests. You can run up to {RATE_LIMIT_MAX} checks "
            f"per {RATE_LIMIT_WINDOW} seconds."
        )
        return

    # ---- Sidebar ----
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
                # Check size BEFORE reading into memory
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

    # ---- Main area ----
    if "results_df" not in st.session_state:
        st.session_state["results_df"] = None

    if not run:
        if st.session_state["results_df"] is not None:
            st.subheader("Previous Results")
            _render_results(st.session_state["results_df"])
        else:
            st.info("Configure your input in the sidebar, then click **Run Check**.")
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
