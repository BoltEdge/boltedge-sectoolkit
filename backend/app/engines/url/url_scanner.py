"""
SecToolkit 101 â€” URL Scanner Engine
"""
import httpx
from urllib.parse import urlparse
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config


_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz",
    ".club", ".work", ".icu", ".cam", ".rest", ".surf",
}

_SUSPICIOUS_PATTERNS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "paypal", "microsoft", "apple", "google",
    "confirm", "suspend", "unlock", "restore",
]


class URLScannerEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def scan(self, url: str) -> dict:
        url = validate_url(url)
        parsed = urlparse(url)
        try:
            static = self._static_analysis(url, parsed)
            redirect_chain = self._follow_redirects(url)
            risk = self._calculate_risk(static, redirect_chain)
            return {
                "url": url,
                "parsed": {"scheme": parsed.scheme, "hostname": parsed.hostname, "port": parsed.port,
                           "path": parsed.path, "query": parsed.query, "fragment": parsed.fragment},
                "static_analysis": static, "redirect_chain": redirect_chain, "risk": risk,
            }
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"URL scan failed: {str(e)}")

    def _static_analysis(self, url, parsed) -> dict:
        hostname = parsed.hostname or ""
        full = url.lower()
        has_ip = self._is_ip_based(hostname)
        suspicious_tld = any(hostname.endswith(tld) for tld in _SUSPICIOUS_TLDS)
        has_suspicious_keywords = any(p in full for p in _SUSPICIOUS_PATTERNS)
        excessive_subdomains = hostname.count(".") > 3
        long_url = len(url) > 200
        has_at_symbol = "@" in url
        has_double_slash = "//" in parsed.path
        uses_https = parsed.scheme == "https"
        has_port = parsed.port is not None and parsed.port not in (80, 443)

        indicators = []
        if has_ip: indicators.append("IP-based URL (no domain name)")
        if suspicious_tld: indicators.append("Suspicious TLD commonly used in phishing")
        if has_suspicious_keywords: indicators.append("Contains phishing-related keywords")
        if excessive_subdomains: indicators.append("Excessive subdomains")
        if long_url: indicators.append("Unusually long URL")
        if has_at_symbol: indicators.append("Contains @ symbol (potential redirect trick)")
        if has_double_slash: indicators.append("Double slash in path (potential redirect)")
        if not uses_https: indicators.append("Does not use HTTPS")
        if has_port: indicators.append(f"Non-standard port: {parsed.port}")

        return {
            "uses_https": uses_https, "is_ip_based": has_ip, "suspicious_tld": suspicious_tld,
            "suspicious_keywords": has_suspicious_keywords, "excessive_subdomains": excessive_subdomains,
            "long_url": long_url, "has_at_symbol": has_at_symbol, "url_length": len(url),
            "indicator_count": len(indicators), "indicators": indicators,
        }

    def _follow_redirects(self, url) -> dict:
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, max_redirects=10) as client:
                response = client.get(url)
                chain = [{"url": str(r.url), "status_code": r.status_code} for r in response.history]
                chain.append({"url": str(response.url), "status_code": response.status_code})
                return {
                    "final_url": str(response.url), "redirects": len(response.history),
                    "chain": chain, "crossed_domains": self._crossed_domains(chain),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "server": response.headers.get("server", ""),
                }
        except httpx.TimeoutException:
            return {"final_url": None, "redirects": 0, "chain": [], "crossed_domains": False, "status_code": None, "error": "Request timed out"}
        except Exception as e:
            return {"final_url": None, "redirects": 0, "chain": [], "crossed_domains": False, "status_code": None, "error": str(e)}

    @staticmethod
    def _crossed_domains(chain) -> bool:
        domains = set()
        for entry in chain:
            p = urlparse(entry["url"])
            if p.hostname: domains.add(p.hostname)
        return len(domains) > 1

    @staticmethod
    def _is_ip_based(hostname) -> bool:
        import ipaddress
        try: ipaddress.ip_address(hostname); return True
        except ValueError: return False

    @staticmethod
    def _calculate_risk(static, redirects) -> dict:
        score = 0
        reasons = []
        score += static.get("indicator_count", 0) * 15
        if redirects.get("crossed_domains"): score += 20; reasons.append("Redirects cross different domains")
        if redirects.get("redirects", 0) > 3: score += 15; reasons.append("Excessive redirects")
        if static.get("is_ip_based"): score += 25
        score = min(score, 100)
        if score >= 75: level = "critical"
        elif score >= 50: level = "high"
        elif score >= 25: level = "medium"
        elif score > 0: level = "low"
        else: level = "clean"
        return {"score": score, "level": level, "reasons": static.get("indicators", []) + reasons}
