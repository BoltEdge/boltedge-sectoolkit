"""
BoltEdge SecToolkit â€” BIMI Checker Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class BIMICheckerEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def check(self, domain: str, selector: str = "default") -> dict:
        domain = validate_domain(domain)
        try:
            query = f"{selector}._bimi.{domain}"
            txt_records = self.dns.resolve(query, "TXT")
            bimi_records = [r.strip('"') for r in txt_records if "v=bimi1" in r.lower()]
            if not bimi_records:
                return {"domain": domain, "selector": selector, "has_bimi": False,
                        "record": None, "logo_url": None, "vmc_url": None,
                        "issues": ["No BIMI record found"]}
            record = bimi_records[0]
            parsed = self._parse_bimi(record)
            issues = self._validate(parsed)
            return {"domain": domain, "selector": selector, "has_bimi": True, "record": record,
                    "logo_url": parsed.get("l"), "vmc_url": parsed.get("a"),
                    "has_logo": bool(parsed.get("l")), "has_vmc": bool(parsed.get("a")), "issues": issues}
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"BIMI check failed: {str(e)}")

    @staticmethod
    def _parse_bimi(record):
        parsed = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part: key, value = part.split("=", 1); parsed[key.strip().lower()] = value.strip()
        return parsed

    @staticmethod
    def _validate(parsed):
        issues = []
        logo = parsed.get("l", "")
        if not logo: issues.append("No logo URL specified (l= tag is empty)")
        elif not logo.startswith("https://"): issues.append("Logo URL must use HTTPS")
        elif not logo.lower().endswith(".svg"): issues.append("Logo should be in SVG Tiny PS format")
        if not parsed.get("a"): issues.append("No VMC certificate â€” logo may not display in all clients")
        return issues
