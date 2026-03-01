"""
BoltEdge SecToolkit â€” Link Extractor Engine
"""
import httpx
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config


class LinkExtractorEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def extract(self, url: str) -> dict:
        url = validate_url(url)
        parsed_base = urlparse(url)
        base_domain = parsed_base.hostname
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url)
            if "text/html" not in response.headers.get("content-type", ""):
                return {"url": url, "error": "Response is not HTML", "content_type": response.headers.get("content-type"), "links": []}
            soup = BeautifulSoup(response.text, "html.parser")
            links = []; seen = set()
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")): continue
                absolute = urljoin(url, href)
                if absolute in seen: continue
                seen.add(absolute)
                link_parsed = urlparse(absolute)
                is_internal = link_parsed.hostname == base_domain
                links.append({"url": absolute, "text": tag.get_text(strip=True)[:200] or None,
                              "rel": tag.get("rel", []), "target": tag.get("target"),
                              "is_internal": is_internal, "is_secure": link_parsed.scheme == "https",
                              "domain": link_parsed.hostname})
            internal = [l for l in links if l["is_internal"]]
            external = [l for l in links if not l["is_internal"]]
            external_domains = list(set(l["domain"] for l in external if l["domain"]))
            return {"url": url, "total_links": len(links), "internal_count": len(internal),
                    "external_count": len(external), "external_domains": sorted(external_domains),
                    "external_domain_count": len(external_domains), "links": links}
        except httpx.TimeoutException: raise EngineTimeoutError(f"Request timed out for {url}")
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"Link extraction failed: {str(e)}")
