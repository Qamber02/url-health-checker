"""
URL Health Checker — Production-ready Streamlit app.

Usage:
    streamlit run url_health_checker.py

Requirements:
    pip install streamlit pandas requests urllib3
"""

import io
import logging
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

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
MAX_INPUT_BYTES = 1 * 1024 * 1024     # 1 MB guard
MAX_WORKERS     = 10                  # conservative; enough for most batches
DEFAULT_TIMEOUT = 5                   # seconds
MAX_URLS        = 500                 # prevent accidental DDoS
USER_AGENT      = (
    "Mozilla/5.0 (compatible; URLHealthChecker/1.0; "
    "+https://github.com/your-org/url-health-checker)"
)
RETRY_TOTAL         = 2
RETRY_BACKOFF       = 0.3
RETRY_STATUS_CODES  = (429, 500, 502, 503, 504)


# ---------------------------------------------------------------------------
# Config dataclass — single source of truth for run settings
# ---------------------------------------------------------------------------
@dataclass
class CheckerConfig:
    timeout:     int  = DEFAULT_TIMEOUT
    max_workers: int  = MAX_WORKERS
    use_head:    bool = True          # try HEAD before GET
    follow_redirects: bool = True


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
class Extractor:
    def extract(self, text: str) -> list[str]:
        raise NotImplementedError


class URLExtractor(Extractor):
    """Extracts unique, validated http/https URLs from arbitrary text."""

    _PATTERN = re.compile(r'https?://[^\s\[\]"<>{}|\\^`]+')

    # Domains that are almost always false-positives in logs/text
    _BLOCKLIST = frozenset({"example.com", "localhost"})

    def extract(self, text: str) -> list[str]:
        found = self._PATTERN.findall(text)
        seen:   set[str]  = set()
        unique: list[str] = []

        for raw in found:
            url = raw.rstrip(".,;:)")   # strip trailing punctuation
            if not self._is_valid(url):
                continue
            if url not in seen:
                seen.add(url)
                unique.append(url)

        logger.info("Extracted %d unique URL(s).", len(unique))

        if len(unique) > MAX_URLS:
            logger.warning(
                "Clamping URL list from %d to %d.", len(unique), MAX_URLS
            )
            unique = unique[:MAX_URLS]

        return unique

    @staticmethod
    def _is_valid(url: str) -> bool:
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
    status_code:      Optional[int]  = None
    response_time_ms: Optional[int]  = None
    final_url:        str            = ""
    error:            str            = ""
    method_used:      str            = ""

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


# Thread-local sessions: one per worker thread (thread-safe, efficient)
_thread_local = threading.local()


def _get_session(config: CheckerConfig) -> requests.Session:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = _make_session(config)
    return _thread_local.session


class URLTester:
    """Tests a single URL and returns a URLResult."""

    def __init__(self, config: CheckerConfig):
        self.config = config

    def test(self, url: str) -> URLResult:
        session = _get_session(self.config)

        # Optionally try HEAD first (faster, lower bandwidth)
        if self.config.use_head:
            result = self._request(session, "HEAD", url)
            # Fall back to GET if server doesn't support HEAD
            if result.error or result.status_code in (405, 501):
                result = self._request(session, "GET", url)
        else:
            result = self._request(session, "GET", url)

        return result

    def _request(self, session: requests.Session, method: str, url: str) -> URLResult:
        start = time.perf_counter()
        try:
            resp = session.request(
                method,
                url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
                stream=True,   # don't download body for HEAD-like efficiency
            )
            resp.close()       # release connection back to pool immediately
            elapsed_ms = round((time.perf_counter() - start) * 1000)

            final = resp.url if resp.url != url else ""
            logger.info(
                "%-8s %-60s  %d  (%d ms)", method, url, resp.status_code, elapsed_ms
            )
            return URLResult(
                url=url,
                status_code=resp.status_code,
                response_time_ms=elapsed_ms,
                final_url=final,
                method_used=method,
            )

        except requests.exceptions.Timeout:
            logger.warning("Timeout [%s]: %s", method, url)
            return URLResult(url=url, error="Timeout", method_used=method)

        except requests.exceptions.TooManyRedirects:
            logger.warning("Too many redirects [%s]: %s", method, url)
            return URLResult(url=url, error="Too many redirects", method_used=method)

        except requests.exceptions.SSLError as exc:
            logger.warning("SSL error [%s]: %s — %s", method, url, exc)
            return URLResult(url=url, error=f"SSL error: {exc}", method_used=method)

        except requests.exceptions.ConnectionError:
            logger.warning("Connection error [%s]: %s", method, url)
            return URLResult(url=url, error="Connection error", method_used=method)

        except requests.RequestException as exc:
            logger.warning("Request failed [%s] %s: %s", method, url, exc)
            return URLResult(url=url, error=str(exc), method_used=method)


# ---------------------------------------------------------------------------
# Health Manager
# ---------------------------------------------------------------------------
class HealthManager:
    """Orchestrates extraction + concurrent testing."""

    def __init__(self, extractor: Extractor, tester: URLTester):
        self.extractor = extractor
        self.tester    = tester

    def run(
        self,
        text:        str,
        progress_cb  = None,   # optional callable(done: int, total: int)
    ) -> list[URLResult]:
        urls = self.extractor.extract(text)
        if not urls:
            return []

        results:  list[URLResult] = []
        done_count = 0
        total      = len(urls)

        max_w = min(self.tester.config.max_workers, total)
        with ThreadPoolExecutor(max_workers=max_w) as pool:
            futures = {pool.submit(self.tester.test, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error("Unexpected error for %s: %s", url, exc)
                    results.append(
                        URLResult(url=url, error=f"Unexpected: {exc}")
                    )
                finally:
                    done_count += 1
                    if progress_cb:
                        progress_cb(done_count, total)

        # Re-sort to original extraction order
        order = {url: i for i, url in enumerate(urls)}
        results.sort(key=lambda r: order.get(r.url, 9999))
        return results


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
    c1.metric("Total URLs",  total)
    c2.metric("✅ Healthy",  ok)
    c3.metric("🟡 Redirects", warns)
    c4.metric("❌ Issues",   errors)


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

    csv_bytes = df.to_csv(index=False).encode("utf-8")
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

    # ---- Sidebar ----
    with st.sidebar:
        st.header("⚙️ Settings")
        timeout = st.slider(
            "Request timeout (seconds)", min_value=1, max_value=30,
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
                "Upload a text file",
                type=["txt", "md", "log", "csv", "json", "html", "xml"],
            )
            if uploaded is not None:
                raw = uploaded.read()
                if len(raw) > MAX_INPUT_BYTES:
                    st.error(
                        f"File too large ({len(raw) // 1024} KB). "
                        f"Maximum is {MAX_INPUT_BYTES // 1024} KB."
                    )
                    return
                try:
                    input_text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    st.error(
                        "Could not decode file. Please upload a UTF-8 encoded text file."
                    )
                    return

        run = st.button("🚀 Run Check", type="primary", use_container_width=True)

    # ---- Main area ----
    # Preserve results across Streamlit reruns (e.g. download button click)
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

    config  = CheckerConfig(
        timeout=timeout,
        max_workers=max_workers,
        use_head=use_head,
        follow_redirects=follow_redirects,
    )
    extractor = URLExtractor()
    tester    = URLTester(config)
    manager   = HealthManager(extractor, tester)

    # Pre-extract to show URL count before testing
    urls = extractor.extract(input_text)
    if not urls:
        st.warning("No valid URLs found in the provided input.")
        return

    st.info(f"Found **{len(urls)}** URL(s). Testing now…")

    progress_bar  = st.progress(0.0)
    status_text   = st.empty()

    def on_progress(done: int, total: int) -> None:
        pct = done / total
        progress_bar.progress(pct)
        status_text.text(f"Checked {done} / {total} URLs…")

    results = manager.run(input_text, progress_cb=on_progress)

    progress_bar.empty()
    status_text.empty()

    if not results:
        st.warning("No results returned.")
        return

    df = pd.DataFrame([r.to_dict() for r in results])
    st.session_state["results_df"] = df

    st.subheader("Results")
    _render_results(df)


if __name__ == "__main__":
    main()
