"""
SecToolkit 101 â€” Tech Stack Detector Engine
"""
import httpx
import re
from bs4 import BeautifulSoup
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config

_SIGNATURES = {
    "cms": {
        "WordPress": [{"type": "html", "pattern": r"wp-content|wp-includes"}, {"type": "meta", "name": "generator", "pattern": r"WordPress"}],
        "Drupal": [{"type": "header", "key": "x-generator", "pattern": r"Drupal"}],
        "Shopify": [{"type": "html", "pattern": r"cdn\.shopify\.com|Shopify\.theme"}],
        "Squarespace": [{"type": "html", "pattern": r"squarespace\.com|static\.squarespace"}],
        "Wix": [{"type": "html", "pattern": r"wix\.com|wixstatic\.com"}],
    },
    "framework": {
        "React": [{"type": "html", "pattern": r"__NEXT_DATA__|_react|reactRoot"}],
        "Next.js": [{"type": "html", "pattern": r"__NEXT_DATA__|_next/static"}],
        "Vue.js": [{"type": "html", "pattern": r"__vue|vue-app|v-cloak"}],
        "Nuxt.js": [{"type": "html", "pattern": r"__NUXT__|_nuxt/"}],
        "Angular": [{"type": "html", "pattern": r"ng-version|ng-app|angular\.js"}],
        "Svelte": [{"type": "html", "pattern": r"svelte-|__sveltekit"}],
        "Laravel": [{"type": "header", "key": "set-cookie", "pattern": r"laravel_session"}],
        "Django": [{"type": "html", "pattern": r"csrfmiddlewaretoken"}],
        "ASP.NET": [{"type": "header", "key": "x-powered-by", "pattern": r"ASP\.NET"}],
    },
    "server": {
        "Nginx": [{"type": "header", "key": "server", "pattern": r"nginx"}],
        "Apache": [{"type": "header", "key": "server", "pattern": r"Apache"}],
        "Cloudflare": [{"type": "header", "key": "server", "pattern": r"cloudflare"}],
        "IIS": [{"type": "header", "key": "server", "pattern": r"Microsoft-IIS"}],
        "Vercel": [{"type": "header", "key": "server", "pattern": r"Vercel"}],
        "Netlify": [{"type": "header", "key": "server", "pattern": r"Netlify"}],
    },
    "analytics": {
        "Google Analytics": [{"type": "html", "pattern": r"google-analytics\.com|gtag|googletagmanager"}],
        "Facebook Pixel": [{"type": "html", "pattern": r"connect\.facebook\.net|fbq\("}],
        "Hotjar": [{"type": "html", "pattern": r"hotjar\.com|hj\("}],
    },
    "cdn": {
        "Cloudflare CDN": [{"type": "header", "key": "cf-ray", "pattern": r".+"}],
        "AWS CloudFront": [{"type": "header", "key": "x-amz-cf-id", "pattern": r".+"}],
        "Fastly": [{"type": "header", "key": "x-served-by", "pattern": r"cache-"}],
    },
}

class TechStackDetectorEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def detect(self, url: str) -> dict:
        url = validate_url(url)
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            detected = {}; total = 0
            for category, techs in _SIGNATURES.items():
                found = []
                for tech_name, sigs in techs.items():
                    if self._match(sigs, headers, html, soup): found.append(tech_name); total += 1
                if found: detected[category] = found
            return {"url": url, "final_url": str(response.url), "total_detected": total, "technologies": detected}
        except httpx.TimeoutException: raise EngineTimeoutError(f"Request timed out for {url}")
        except Exception as e: raise EngineError(f"Tech stack detection failed: {str(e)}")

    @staticmethod
    def _match(sigs, headers, html, soup) -> bool:
        for sig in sigs:
            try:
                if sig["type"] == "header" and re.search(sig["pattern"], headers.get(sig["key"], ""), re.IGNORECASE): return True
                elif sig["type"] == "html" and re.search(sig["pattern"], html, re.IGNORECASE): return True
                elif sig["type"] == "meta":
                    meta = soup.find("meta", attrs={"name": sig["name"]})
                    if meta and re.search(sig["pattern"], meta.get("content", ""), re.IGNORECASE): return True
            except Exception: continue
        return False
