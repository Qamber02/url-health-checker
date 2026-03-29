"""
URL Health Checker — Production-ready Streamlit app.

Usage:
    streamlit run url_health_checker.py

Requirements:
    pip install streamlit pandas requests
"""

import io
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
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
MAX_INPUT_BYTES = 1 * 1024 * 1024   # 1 MB guard
MAX_WORKERS = 20                     # concurrent request threads
DEFAULT_TIMEOUT = 5                  # seconds


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
class Extractor:
    def extract(self, text: str) -> list[str]:
        raise NotImplementedError


class URLExtractor(Extractor):
    """Extracts unique http/https URLs from arbitrary text."""

    _PATTERN = re.compile(r'https?://[^\s\[\]"<>]+')

    def extract(self, text: str) -> list[str]:
        found = self._PATTERN.findall(text)
        # Deduplicate while preserving first-seen order
        seen: set[str] = set()
        unique: list[str] = []
        for url in found:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        logger.info("Extracted %d unique URL(s).", len(unique))
        return unique


# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
class URLTester:
    """Tests a single URL and returns a result dict."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._session = requests.Session()
        self._session.max_redirects = 10

    def test(self, url: str) -> dict:
        start = time.perf_counter()
        try:
            resp = self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
            )
            elapsed_ms = round((time.perf_counter() - start) * 1000)
            logger.info("%-60s  %d  (%d ms)", url, resp.status_code, elapsed_ms)
            return {
                "url": url,
                "status_code": resp.status_code,
                "response_time_ms": elapsed_ms,
                "final_url": resp.url if resp.url != url else "",
                "error": "",
            }
        except requests.exceptions.Timeout:
            logger.warning("Timeout: %s", url)
            return _error_result(url, "Timeout")
        except requests.exceptions.TooManyRedirects:
            logger.warning("Too many redirects: %s", url)
            return _error_result(url, "Too many redirects")
        except requests.exceptions.ConnectionError:
            logger.warning("Connection error: %s", url)
            return _error_result(url, "Connection error")
        except requests.RequestException as exc:
            logger.warning("Request failed for %s: %s", url, exc)
            return _error_result(url, str(exc))


def _error_result(url: str, reason: str) -> dict:
    return {
        "url": url,
        "status_code": None,
        "response_time_ms": None,
        "final_url": "",
        "error": reason,
    }


# ---------------------------------------------------------------------------
# Health Manager
# ---------------------------------------------------------------------------
class HealthManager:
    """Orchestrates extraction + concurrent testing."""

    def __init__(self, extractor: Extractor, tester: URLTester):
        self.extractor = extractor
        self.tester = tester

    def run(self, text: str) -> list[dict]:
        urls = self.extractor.extract(text)
        if not urls:
            return []

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(self.tester.test, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:          # pragma: no cover
                    url = futures[future]
                    logger.error("Unexpected error for %s: %s", url, exc)
                    results.append(_error_result(url, f"Unexpected: {exc}"))

        # Re-sort to match original extraction order
        order = {url: i for i, url in enumerate(urls)}
        results.sort(key=lambda r: order.get(r["url"], 9999))
        return results


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
def _status_color(code) -> str:
    if code is None:
        return "🔴"
    if 200 <= code < 300:
        return "🟢"
    if 300 <= code < 400:
        return "🟡"
    return "🔴"


def _render_results(df: pd.DataFrame) -> None:
    # Summary banner
    total = len(df)
    ok = int((df["status_code"].between(200, 299, inclusive="both")).sum())
    errors = total - ok
    c1, c2, c3 = st.columns(3)
    c1.metric("Total URLs", total)
    c2.metric("✅ Healthy", ok)
    c3.metric("❌ Issues", errors)

    # Colour-coded status column
    display_df = df.copy()
    display_df.insert(
        0,
        "health",
        display_df["status_code"].apply(_status_color),
    )
    display_df.rename(
        columns={
            "health": "",
            "url": "URL",
            "status_code": "Status",
            "response_time_ms": "Response (ms)",
            "final_url": "Final URL (redirect)",
            "error": "Error",
        },
        inplace=True,
    )

    st.dataframe(display_df, use_container_width=True, hide_index=True)

    # CSV export
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Export as CSV",
        data=csv_bytes,
        file_name="url_health_results.csv",
        mime="text/csv",
    )


def main() -> None:
    st.set_page_config(page_title="URL Health Checker", page_icon="🔗", layout="wide")
    st.title("🔗 URL Health Checker")
    st.caption("Extract, test, and monitor URLs from any text or file.")

    # Sidebar — inputs
    with st.sidebar:
        st.header("⚙️ Settings")
        timeout = st.slider("Request timeout (seconds)", 1, 30, DEFAULT_TIMEOUT)

        st.divider()
        st.header("📥 Input")
        mode = st.radio("Input mode", ("Paste Text", "Upload File"), horizontal=True)

        input_text = ""
        if mode == "Paste Text":
            input_text = st.text_area("Paste your text here", height=220)
        else:
            uploaded = st.file_uploader(
                "Upload a text file", type=["txt", "md", "log", "csv", "json"]
            )
            if uploaded is not None:
                raw = uploaded.read()
                if len(raw) > MAX_INPUT_BYTES:
                    st.error(
                        f"File too large ({len(raw) // 1024} KB). "
                        f"Maximum allowed is {MAX_INPUT_BYTES // 1024} KB."
                    )
                    return
                try:
                    input_text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    st.error("Could not decode file. Please upload a UTF-8 encoded text file.")
                    return

        run = st.button("🚀 Run Check", type="primary", use_container_width=True)

    # Main area
    if not run:
        st.info("Configure your input in the sidebar, then click **Run Check**.")
        return

    if not input_text.strip():
        st.warning("Please provide some text or upload a file first.")
        return

    extractor = URLExtractor()
    tester = URLTester(timeout=timeout)
    manager = HealthManager(extractor, tester)

    with st.spinner("Testing URLs — hang tight..."):
        results = manager.run(input_text)

    if not results:
        st.warning("No URLs found in the provided input.")
        return

    df = pd.DataFrame(results)
    st.subheader("Results")
    _render_results(df)


if __name__ == "__main__":
    main()
