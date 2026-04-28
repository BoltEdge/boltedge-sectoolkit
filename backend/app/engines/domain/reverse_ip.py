"""
SecToolkit 101 â€” Reverse IP Engine

Tool: Domain -> Reverse IP
Description: Find domains hosted on the same IP.
Input: Domain name or IP address
Output: List of domains sharing the same IP, hosting info
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_domain, validate_ip


class ReverseIPEngine:
    """Find domains hosted on the same IP address."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, target: str) -> dict:
        ip_address = self._resolve_to_ip(target)

        try:
            ptr_records = self.dns.reverse_lookup(ip_address)

            associated = []
            for hostname in ptr_records:
                try:
                    a_records = self.dns.resolve(hostname, "A")
                    associated.append({
                        "domain": hostname,
                        "a_records": a_records,
                        "confirmed": ip_address in a_records,
                    })
                except (EngineError, EngineTimeoutError):
                    associated.append({
                        "domain": hostname,
                        "a_records": [],
                        "confirmed": False,
                    })

            return {
                "target": target,
                "ip": ip_address,
                "ptr_records": ptr_records,
                "associated_domains": associated,
                "total_found": len(associated),
                "note": "Full reverse IP lookup requires external data sources. "
                        "Results shown are based on DNS PTR records only.",
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"Reverse IP lookup failed: {str(e)}")

    def _resolve_to_ip(self, target: str) -> str:
        target = target.strip()
        try:
            return validate_ip(target)
        except InvalidInputError:
            pass
        try:
            domain = validate_domain(target)
            a_records = self.dns.resolve(domain, "A")
            if a_records:
                return a_records[0]
            raise EngineError(f"Could not resolve {domain} to an IP address")
        except InvalidInputError:
            raise InvalidInputError(f"Not a valid domain or IP address: {target}")
