

import re
import requests
import streamlit as st
import pandas as pd


class Extractor:
    def extract(self, text: str) -> list:
        raise NotImplementedError("extract method must be implemented by subclasses")


class URLExtractor(Extractor):
    def __init__(self):
        self.__pattern = re.compile(r'https?://[^\s\[\]"<>]+')

    def extract(self, text: str) -> list:
        return self.__pattern.findall(text)


class Tester:
    def can_handle(self, url: str) -> bool:
        raise NotImplementedError("can_handle must be implemented by subclasses")

    def test(self, url: str) -> int:
        raise NotImplementedError("test must be implemented by subclasses")


class HTTPTester(Tester):
    def can_handle(self, url: str) -> bool:
        return url.startswith("http://")

    def test(self, url: str) -> int:
        try:
            resp = requests.get(url, timeout=5)
            return resp.status_code
        except requests.RequestException:
            return None


class HTTPSTester(Tester):
    def can_handle(self, url: str) -> bool:
        return url.startswith("https://")

    def test(self, url: str) -> int:
        try:
            resp = requests.get(url, timeout=5)
            return resp.status_code
        except requests.RequestException:
            return None


class HealthManager:
    def __init__(self, extractor: Extractor, testers: list):
        self.extractor = extractor
        self.testers = testers

    def run(self, text: str) -> list:
        urls = self.extractor.extract(text)
        results = []

        for url in urls:
            status = None
            for tester in self.testers:
                if tester.can_handle(url):
                    status = tester.test(url)
                    break
            results.append({"url": url, "status_code": status})

        return results


def main():
    st.title("URL Health Checker")

    mode = st.sidebar.radio("Choose input mode", ("Paste Text", "Upload File"))

    input_text = ""
    if mode == "Paste Text":
        input_text = st.sidebar.text_area("Paste your text here", height=200)
    else:
        uploaded = st.sidebar.file_uploader("Upload a text file", type=["txt", "md", "log"])
        if uploaded is not None:
            try:
                input_text = uploaded.read().decode("utf-8")
            except Exception:
                input_text = ""

    if st.sidebar.button("Run Check"):
        if not input_text.strip():
            st.warning("Please provide text or upload a file first.")
            return

        extractor = URLExtractor()
        testers = [HTTPTester(), HTTPSTester()]
        manager = HealthManager(extractor, testers)

        results = manager.run(input_text)
        df = pd.DataFrame(results)

        st.subheader("Results")
        st.dataframe(df)
        st.markdown("- Click column headers to sort.\n- Status code None means request failed.")


if __name__ == "__main__":
    main()

