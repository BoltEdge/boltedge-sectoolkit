"""
BoltEdge SecToolkit â€” NS Records Engine

Tool: Domain -> NS Records
Description: Look up nameserver records.
Input: Domain name
Output: NS records with IP addresses and provider detection
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


_DNS_PROVIDERS = {
    "cloudflare.com": "Cloudflare",
    "awsdns": "AWS Route 53",
    "azure-dns": "Microsoft Azure DNS",
    "googledomains.com": "Google Domains",
    "google.com": "Google Cloud DNS",
    "domaincontrol.com": "GoDaddy",
    "registrar-servers.com": "Namecheap",
    "digitalocean.com": "DigitalOcean",
    "linode.com": "Linode/Akamai",
    "hetzner.com": "Hetzner",
    "ovh.net": "OVH",
    "dnsimple.com": "DNSimple",
    "nsone.net": "NS1/IBM",
    "dynect.net": "Oracle Dyn",
    "ultradns": "Neustar UltraDNS",
    "name-services.com": "Enom",
    "worldnic.com": "Network Solutions",
}


class NSRecordsEngine:
    """NS record lookup with provider detection."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            ns_records = self.dns.resolve(domain, "NS")

            if not ns_records:
                return {
                    "domain": domain,
                    "has_ns": False,
                    "total_records": 0,
                    "records": [],
                    "provider": None,
                }

            parsed = []
            for ns in ns_records:
                hostname = ns.rstrip(".")
                a_records = self._safe_resolve(hostname, "A")
                aaaa_records = self._safe_resolve(hostname, "AAAA")
                parsed.append({
                    "hostname": hostname,
                    "a_records": a_records,
                    "aaaa_records": aaaa_records,
                })

            provider = self._detect_provider(parsed)

            return {
                "domain": domain,
                "has_ns": True,
                "total_records": len(parsed),
                "records": parsed,
                "provider": provider,
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"NS lookup failed: {str(e)}")

    def _safe_resolve(self, hostname: str, record_type: str) -> list[str]:
        try:
            return self.dns.resolve(hostname, record_type)
        except (EngineError, EngineTimeoutError):
            return []

    @staticmethod
    def _detect_provider(records: list[dict]) -> str | None:
        for record in records:
            hostname = record["hostname"].lower()
            for pattern, provider in _DNS_PROVIDERS.items():
                if pattern in hostname:
                    return provider
        return None
