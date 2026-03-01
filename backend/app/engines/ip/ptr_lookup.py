"""
BoltEdge SecToolkit — PTR Lookup Engine

Tool: IP → PTR Lookup
Description: Query PTR records for IP addresses.
Input: IPv4 or IPv6 address
Output: PTR records, reverse DNS zone, delegation info

Dependencies:
  - app/engines/common/dns_resolver.py

Used by:
  - PTR Lookup tool (primary)
  - Reverse DNS (shares logic, PTR is more detailed/raw)
  - Email → MX Check (PTR validation for mail servers)

Difference from Reverse DNS tool:
  - Reverse DNS: high-level lookup with FCrDNS verification
  - PTR Lookup: lower-level, shows the raw PTR zone, delegation,
    and multiple nameserver responses
"""
import dns.reversename
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_ip


# Common public DNS servers for multi-resolver comparison
_PUBLIC_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}


class PTRLookupEngine:
    """Detailed PTR record lookup with zone and delegation info."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, ip_address: str) -> dict:
        """Perform detailed PTR lookup for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with PTR records, reverse zone, delegation, multi-resolver results.

        Raises:
            InvalidInputError: If IP is not valid.
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        try:
            # Build the reverse DNS name
            reverse_name = str(dns.reversename.from_address(ip_address))
            reverse_zone = self._get_reverse_zone(ip_address)

            # Primary PTR lookup
            ptr_records = self.dns.reverse_lookup(ip_address)

            # Get zone delegation (NS records for the reverse zone)
            delegation = self._get_delegation(reverse_zone)

            # Multi-resolver comparison
            multi_resolver = self._multi_resolver_lookup(ip_address)

            return {
                "ip": ip_address,
                "reverse_name": reverse_name,
                "reverse_zone": reverse_zone,
                "ptr_records": ptr_records,
                "has_ptr": len(ptr_records) > 0,
                "record_count": len(ptr_records),
                "delegation": delegation,
                "multi_resolver": multi_resolver,
                "consistent": self._check_consistency(multi_resolver),
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"PTR lookup failed: {str(e)}")

    def _get_reverse_zone(self, ip_address: str) -> str:
        """Determine the reverse DNS zone for an IP.

        Returns:
            Reverse zone string (e.g. "1.168.192.in-addr.arpa").
        """
        if ":" in ip_address:
            # IPv6 — use ip6.arpa
            reverse_name = str(dns.reversename.from_address(ip_address))
            # Strip the host part, keep the /48 zone
            parts = reverse_name.rstrip(".").split(".")
            # Return the zone portion (last ~20 labels)
            return ".".join(parts[-20:]) + "."
        else:
            # IPv4 — use first 3 octets for /24 zone
            octets = ip_address.split(".")
            return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."

    def _get_delegation(self, reverse_zone: str) -> dict:
        """Get NS delegation for the reverse zone.

        Returns:
            Dict with nameservers and SOA info.
        """
        try:
            ns_records = self.dns.resolve(reverse_zone, "NS")
            soa_records = self.dns.resolve(reverse_zone, "SOA")

            return {
                "nameservers": ns_records,
                "soa": soa_records[0] if soa_records else None,
                "delegated": len(ns_records) > 0,
            }
        except (EngineError, EngineTimeoutError):
            return {
                "nameservers": [],
                "soa": None,
                "delegated": False,
            }

    def _multi_resolver_lookup(self, ip_address: str) -> list[dict]:
        """Query PTR across multiple public resolvers for comparison.

        Returns:
            List of dicts with resolver name, IP, and PTR results.
        """
        results = []

        for name, resolver_ip in _PUBLIC_RESOLVERS.items():
            try:
                custom_dns = DNSResolver(nameservers=[resolver_ip])
                ptrs = custom_dns.reverse_lookup(ip_address)
                results.append({
                    "resolver": name,
                    "resolver_ip": resolver_ip,
                    "ptr_records": ptrs,
                    "has_ptr": len(ptrs) > 0,
                    "status": "success",
                })
            except EngineTimeoutError:
                results.append({
                    "resolver": name,
                    "resolver_ip": resolver_ip,
                    "ptr_records": [],
                    "has_ptr": False,
                    "status": "timeout",
                })
            except EngineError:
                results.append({
                    "resolver": name,
                    "resolver_ip": resolver_ip,
                    "ptr_records": [],
                    "has_ptr": False,
                    "status": "error",
                })

        return results

    @staticmethod
    def _check_consistency(multi_resolver: list[dict]) -> bool:
        """Check if all resolvers return the same PTR records."""
        successful = [r for r in multi_resolver if r["status"] == "success"]

        if len(successful) < 2:
            return True

        first = set(successful[0]["ptr_records"])
        return all(set(r["ptr_records"]) == first for r in successful[1:])