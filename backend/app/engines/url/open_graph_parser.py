"""
SecToolkit 101 â€” Open Graph Parser Engine
"""
import httpx
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config


class OpenGraphParserEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def parse(self, url: str) -> dict:
        url = validate_url(url)
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            og = self._extract_og(soup)
            twitter = self._extract_twitter(soup)
            meta = self._extract_meta(soup, url)
            return {"url": url, "final_url": str(response.url), "title": meta.get("title"),
                    "open_graph": og, "twitter_card": twitter, "meta": meta,
                    "has_og": len(og) > 0, "has_twitter_card": len(twitter) > 0}
        except httpx.TimeoutException: raise EngineTimeoutError(f"Request timed out for {url}")
        except Exception as e: raise EngineError(f"Open Graph parsing failed: {str(e)}")

    @staticmethod
    def _extract_og(soup):
        og = {}
        for tag in soup.find_all("meta", attrs={"property": True}):
            prop = tag.get("property", "")
            if prop.startswith("og:"): og[prop[3:]] = tag.get("content", "")
        return og

    @staticmethod
    def _extract_twitter(soup):
        tw = {}
        for tag in soup.find_all("meta", attrs={"name": True}):
            name = tag.get("name", "")
            if name.startswith("twitter:"): tw[name[8:]] = tag.get("content", "")
        return tw

    @staticmethod
    def _extract_meta(soup, base_url):
        meta = {}
        title_tag = soup.find("title")
        meta["title"] = title_tag.get_text(strip=True) if title_tag else None
        for name in ["description", "keywords", "author", "robots"]:
            tag = soup.find("meta", attrs={"name": name})
            meta[name] = tag.get("content", "") if tag else None
        canonical = soup.find("link", attrs={"rel": "canonical"})
        meta["canonical"] = canonical.get("href", "") if canonical else None
        favicon = soup.find("link", attrs={"rel": lambda r: r and "icon" in r})
        meta["favicon"] = urljoin(base_url, favicon.get("href", "")) if favicon else urljoin(base_url, "/favicon.ico")
        html_tag = soup.find("html")
        meta["language"] = html_tag.get("lang") if html_tag else None
        charset = soup.find("meta", attrs={"charset": True})
        meta["charset"] = charset.get("charset") if charset else None
        return meta
