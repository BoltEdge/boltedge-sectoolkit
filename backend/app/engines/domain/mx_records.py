"""
BoltEdge SecToolkit â€” MX Records Engine

Tool: Domain -> MX Records
Description: Look up mail exchange records.
Input: Domain name
Output: MX records with priority, IP addresses, and mail provider detection
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


_MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "microsoft.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "barracuda": "Barracuda",
    "messagelabs": "Symantec/Broadcom",
    "fireeyecloud.com": "FireEye/Trellix",
    "zoho.com": "Zoho Mail",
    "yahoodns.net": "Yahoo Mail",
    "securemx": "Cisco Secure Email",
    "iphmx.com": "Cisco Secure Email",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "postmarkapp.com": "Postmark",
    "mx.cloudflare.net": "Cloudflare Email",
    "protonmail.ch": "ProtonMail",
    "tutanota.de": "Tutanota",
    "fastmail": "Fastmail",
}


class MXRecordsEngine:
    """MX record lookup with provider detection."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            mx_records = self.dns.resolve(domain, "MX")

            if not mx_records:
                return {
                    "domain": domain,
                    "has_mx": False,
                    "total_records": 0,
                    "records": [],
                    "provider": None,
                }

            parsed = []
            for record in mx_records:
                parts = record.split()
                priority = int(parts[0]) if len(parts) >= 2 else 0
                hostname = parts[-1].rstrip(".")

                a_records = self._safe_resolve(hostname, "A")
                aaaa_records = self._safe_resolve(hostname, "AAAA")

                parsed.append({
                    "priority": priority,
                    "hostname": hostname,
                    "a_records": a_records,
                    "aaaa_records": aaaa_records,
                })

            parsed.sort(key=lambda r: r["priority"])
            provider = self._detect_provider(parsed)

            return {
                "domain": domain,
                "has_mx": True,
                "total_records": len(parsed),
                "records": parsed,
                "provider": provider,
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"MX lookup failed: {str(e)}")

    def _safe_resolve(self, hostname: str, record_type: str) -> list[str]:
        try:
            return self.dns.resolve(hostname, record_type)
        except (EngineError, EngineTimeoutError):
            return []

    @staticmethod
    def _detect_provider(records: list[dict]) -> str | None:
        for record in records:
            hostname = record["hostname"].lower()
            for pattern, provider in _MAIL_PROVIDERS.items():
                if pattern in hostname:
                    return provider
        return None
