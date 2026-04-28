"""
SecToolkit 101 â€” HTTP Headers Engine
"""
import httpx
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_url
from app.config import Config

_SECURITY_HEADERS = {
    "strict-transport-security": {"name": "HSTS", "description": "Forces HTTPS connections", "severity": "high"},
    "content-security-policy": {"name": "CSP", "description": "Controls allowed content sources", "severity": "high"},
    "x-frame-options": {"name": "X-Frame-Options", "description": "Prevents clickjacking", "severity": "medium"},
    "x-content-type-options": {"name": "X-Content-Type-Options", "description": "Prevents MIME sniffing", "severity": "medium"},
    "x-xss-protection": {"name": "X-XSS-Protection", "description": "XSS filter (legacy)", "severity": "low"},
    "referrer-policy": {"name": "Referrer-Policy", "description": "Controls referrer information", "severity": "medium"},
    "permissions-policy": {"name": "Permissions-Policy", "description": "Controls browser features", "severity": "medium"},
    "x-permitted-cross-domain-policies": {"name": "Cross-Domain Policies", "description": "Controls Flash/PDF cross-domain access", "severity": "low"},
}

class HTTPHeadersEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def inspect(self, url: str) -> dict:
        url = validate_url(url)
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url)
            headers = dict(response.headers)
            security = self._analyse_security(headers)
            return {"url": url, "final_url": str(response.url), "status_code": response.status_code,
                    "headers": headers, "header_count": len(headers), "security_headers": security,
                    "server": headers.get("server"), "powered_by": headers.get("x-powered-by"),
                    "content_type": headers.get("content-type")}
        except httpx.TimeoutException: raise EngineTimeoutError(f"Request timed out for {url}")
        except Exception as e: raise EngineError(f"Header inspection failed: {str(e)}")

    @staticmethod
    def _analyse_security(headers) -> dict:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        present = []; missing = []
        for hk, info in _SECURITY_HEADERS.items():
            if hk in lower_headers: present.append({"header": info["name"], "value": lower_headers[hk], "status": "present"})
            else: missing.append({"header": info["name"], "description": info["description"], "severity": info["severity"], "status": "missing"})
        total = len(_SECURITY_HEADERS)
        score = round((len(present) / total) * 100) if total > 0 else 0
        return {"score": score, "present": present, "present_count": len(present),
                "missing": missing, "missing_count": len(missing),
                "grade": "A" if score >= 85 else ("B" if score >= 60 else ("C" if score >= 40 else "F"))}
