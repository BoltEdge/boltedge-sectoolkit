"""
SecToolkit 101 â€” TXT Records Engine

Tool: Domain -> TXT Records
Description: Look up TXT records.
Input: Domain name
Output: TXT records with classification (SPF, DKIM, DMARC, verification, etc.)
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class TXTRecordsEngine:
    """TXT record lookup with classification."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            txt_records = self.dns.resolve(domain, "TXT")

            if not txt_records:
                return {
                    "domain": domain,
                    "has_txt": False,
                    "total_records": 0,
                    "records": [],
                    "classifications": {},
                }

            parsed = []
            classifications = {
                "spf": [], "dmarc": [], "dkim": [],
                "verification": [], "security": [], "other": [],
            }

            for record in txt_records:
                value = record.strip('"')
                record_type = self._classify(value)
                entry = {"value": value, "type": record_type, "length": len(value)}
                parsed.append(entry)
                classifications[record_type].append(value)

            return {
                "domain": domain,
                "has_txt": True,
                "total_records": len(parsed),
                "records": parsed,
                "classifications": {k: v for k, v in classifications.items() if v},
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"TXT lookup failed: {str(e)}")

    @staticmethod
    def _classify(value: str) -> str:
        lower = value.lower()
        if lower.startswith("v=spf1"):
            return "spf"
        if lower.startswith("v=dmarc1"):
            return "dmarc"
        if lower.startswith("v=dkim1") or "dkim" in lower:
            return "dkim"

        verification_patterns = [
            "google-site-verification", "facebook-domain-verification",
            "ms=", "apple-domain-verification", "atlassian-domain-verification",
            "docusign=", "hubspot-developer-verification",
            "adobe-idp-site-verification", "stripe-verification",
            "cisco-ci-domain-verification", "dropbox-domain-verification",
            "zoom-domain-verification", "slack-domain-verification",
            "_github-challenge", "blitz=", "onetrust-domain-verification",
        ]
        for pattern in verification_patterns:
            if pattern in lower:
                return "verification"

        security_patterns = ["v=stk1", "ca3-", "_dmarc", "protonmail-verification"]
        for pattern in security_patterns:
            if pattern in lower:
                return "security"

        return "other"
