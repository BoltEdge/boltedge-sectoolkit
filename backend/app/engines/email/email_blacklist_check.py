"""
SecToolkit 101 â€” Email Blacklist Check Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError
from app.utils.validators import validate_domain

_DOMAIN_DNSBLS = [
    {"name": "Spamhaus DBL", "zone": "dbl.spamhaus.org"},
    {"name": "SURBL", "zone": "multi.surbl.org"},
    {"name": "URIBL", "zone": "multi.uribl.com"},
    {"name": "Spamcop", "zone": "bl.spamcop.net"},
    {"name": "Barracuda BRBL", "zone": "b.barracudacentral.org"},
    {"name": "SpamEatingMonkey", "zone": "bl.spameatingmonkey.net"},
]

class EmailBlacklistCheckEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def check(self, domain: str) -> dict:
        domain = validate_domain(domain)
        try:
            results = []; listed_count = 0
            for dnsbl in _DOMAIN_DNSBLS:
                result = self._check_single(domain, dnsbl); results.append(result)
                if result["listed"]: listed_count += 1
            risk = "clean" if listed_count == 0 else ("low" if listed_count <= 1 else ("medium" if listed_count <= 3 else "high"))
            return {"domain": domain, "total_blacklists": len(_DOMAIN_DNSBLS), "listed_count": listed_count,
                    "clean_count": len(_DOMAIN_DNSBLS) - listed_count, "is_clean": listed_count == 0,
                    "risk_level": risk, "results": results}
        except Exception as e: raise EngineError(f"Email blacklist check failed: {str(e)}")

    def _check_single(self, domain, dnsbl):
        query = f"{domain}.{dnsbl['zone']}"
        try:
            responses = self.dns.resolve(query, "A")
            if responses:
                return {"blacklist": dnsbl["name"], "zone": dnsbl["zone"], "listed": True,
                        "return_code": responses[0], "status": "listed"}
        except Exception: pass
        return {"blacklist": dnsbl["name"], "zone": dnsbl["zone"], "listed": False,
                "return_code": None, "status": "clean"}
