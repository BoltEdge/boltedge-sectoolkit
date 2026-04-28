"""
SecToolkit 101 â€” Screenshot Capture Engine (metadata phase)
"""
import httpx
from urllib.parse import urlparse
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config


class ScreenshotCaptureEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def capture(self, url: str) -> dict:
        url = validate_url(url)
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.head(url)
            content_type = response.headers.get("content-type", "")
            return {"url": url, "final_url": str(response.url), "status_code": response.status_code,
                    "is_html": "text/html" in content_type, "content_type": content_type,
                    "server": response.headers.get("server"), "title": None,
                    "screenshot_available": False,
                    "message": "Headless browser integration pending. Page metadata returned for validation."}
        except httpx.TimeoutException: raise EngineTimeoutError(f"Request timed out for {url}")
        except Exception as e: raise EngineError(f"Screenshot capture failed: {str(e)}")
