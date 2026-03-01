"""
BoltEdge SecToolkit â€” DKIM Validator Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain

_COMMON_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "smtp", "email", "s1", "s2", "mx", "mandrill", "everlytickey1", "cm",
    "protonmail", "protonmail2", "protonmail3", "zoho", "zmail", "mailjet",
    "amazonses", "ses",
]

class DKIMValidatorEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def check(self, domain: str, selector: str = None) -> dict:
        domain = validate_domain(domain)
        try:
            if selector: results = [self._check_selector(domain, selector)]
            else: results = self._check_common_selectors(domain)
            found = [r for r in results if r["found"]]
            return {"domain": domain, "has_dkim": len(found) > 0, "selectors_checked": len(results),
                    "selectors_found": len(found), "results": results,
                    "found_selectors": [r["selector"] for r in found]}
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"DKIM check failed: {str(e)}")

    def _check_selector(self, domain, selector):
        query = f"{selector}._domainkey.{domain}"
        try:
            txt_records = self.dns.resolve(query, "TXT")
            if not txt_records: return {"selector": selector, "query": query, "found": False, "record": None, "parsed": None}
            record = txt_records[0].strip('"')
            return {"selector": selector, "query": query, "found": True, "record": record, "parsed": self._parse_dkim(record)}
        except (EngineError, EngineTimeoutError):
            return {"selector": selector, "query": query, "found": False, "record": None, "parsed": None}

    def _check_common_selectors(self, domain):
        return [self._check_selector(domain, s) for s in _COMMON_SELECTORS]

    @staticmethod
    def _parse_dkim(record):
        parsed = {}
        for part in record.replace(" ", "").split(";"):
            if "=" in part:
                key, value = part.split("=", 1); parsed[key.strip().lower()] = value.strip()
        pk = parsed.get("p", "")
        return {"version": parsed.get("v"), "key_type": parsed.get("k", "rsa"),
                "public_key": pk[:50] + "..." if len(pk) > 50 else pk,
                "has_public_key": bool(pk), "key_revoked": pk == "",
                "flags": parsed.get("t"), "notes": parsed.get("n"),
                "hash_algorithms": parsed.get("h"), "service_type": parsed.get("s")}
