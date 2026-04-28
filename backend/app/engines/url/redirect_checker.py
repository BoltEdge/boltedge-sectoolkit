"""
SecToolkit 101 â€” Redirect Checker Engine
"""
import httpx
import time
from urllib.parse import urlparse
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config


class RedirectCheckerEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def check(self, url: str, max_redirects: int = 20) -> dict:
        url = validate_url(url)
        max_redirects = min(max_redirects, 30)
        try:
            chain = []
            current_url = url
            start_time = time.time()
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                for i in range(max_redirects + 1):
                    hop_start = time.time()
                    try: response = client.get(current_url)
                    except httpx.TimeoutException:
                        chain.append({"hop": i + 1, "url": current_url, "status_code": None, "error": "Timed out"}); break
                    hop_time = round((time.time() - hop_start) * 1000, 1)
                    entry = {"hop": i + 1, "url": current_url, "status_code": response.status_code,
                             "status_reason": response.reason_phrase, "response_time_ms": hop_time,
                             "server": response.headers.get("server"), "content_type": response.headers.get("content-type")}
                    if response.is_redirect and "location" in response.headers:
                        location = response.headers["location"]
                        if not location.startswith(("http://", "https://")):
                            p = urlparse(current_url)
                            location = f"{p.scheme}://{p.netloc}{location}" if location.startswith("/") else f"{p.scheme}://{p.netloc}/{location}"
                        entry["redirect_to"] = location
                        entry["redirect_type"] = self._redirect_type(response.status_code)
                        chain.append(entry); current_url = location
                    else:
                        entry["redirect_to"] = None; entry["is_final"] = True
                        chain.append(entry); break
            total_time = round((time.time() - start_time) * 1000, 1)
            domains = self._extract_domains(chain)
            return {
                "url": url, "final_url": chain[-1]["url"] if chain else url,
                "total_redirects": len(chain) - 1, "total_time_ms": total_time,
                "chain": chain, "domains_visited": domains,
                "crossed_domains": len(domains) > 1,
                "final_status": chain[-1]["status_code"] if chain else None,
                "has_redirect_loop": len(chain) > max_redirects,
            }
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"Redirect check failed: {str(e)}")

    @staticmethod
    def _redirect_type(code): return {301: "Permanent (301)", 302: "Found/Temporary (302)", 303: "See Other (303)", 307: "Temporary (307)", 308: "Permanent (308)"}.get(code, f"Redirect ({code})")

    @staticmethod
    def _extract_domains(chain):
        domains = []; seen = set()
        for entry in chain:
            p = urlparse(entry["url"])
            if p.hostname and p.hostname not in seen: seen.add(p.hostname); domains.append(p.hostname)
        return domains
