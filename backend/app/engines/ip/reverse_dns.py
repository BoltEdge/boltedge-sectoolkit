"""
BoltEdge SecToolkit — Reverse DNS Engine

Tool: IP → Reverse DNS
Description: Perform reverse DNS lookup on IP addresses.
Input: IPv4 or IPv6 address
Output: PTR hostnames, forward verification status

Dependencies:
  - app/engines/common/dns_resolver.py

Used by:
  - Reverse DNS tool (primary)
  - IP Geolocation (hostname enrichment)
  - IP Reputation (context)
  - Domain → Reverse IP (verification)
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_ip


class ReverseDNSEngine:
    """Reverse DNS lookup with forward verification."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, ip_address: str) -> dict:
        """Perform reverse DNS lookup for an IP address.

        Also performs forward verification — checks that the returned
        hostname(s) resolve back to the original IP (FCrDNS).

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with PTR records and forward verification results.

        Raises:
            InvalidInputError: If IP is not valid.
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        try:
            hostnames = self.dns.reverse_lookup(ip_address)

            # Forward verification for each hostname
            verified = []
            for hostname in hostnames:
                fwd_check = self._forward_verify(hostname, ip_address)
                verified.append({
                    "hostname": hostname,
                    "forward_verified": fwd_check["verified"],
                    "forward_ips": fwd_check["ips"],
                })

            return {
                "ip": ip_address,
                "ptr_records": hostnames,
                "total_records": len(hostnames),
                "has_ptr": len(hostnames) > 0,
                "verified_hostnames": verified,
                "fcrdns_pass": any(v["forward_verified"] for v in verified),
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"Reverse DNS lookup failed: {str(e)}")

    def _forward_verify(self, hostname: str, original_ip: str) -> dict:
        """Check if a hostname resolves back to the original IP (FCrDNS).

        Args:
            hostname: The PTR hostname to verify.
            original_ip: The original IP address.

        Returns:
            Dict with verified flag and resolved IPs.
        """
        try:
            # Try A records
            a_records = self.dns.resolve(hostname, "A")

            # Try AAAA records
            aaaa_records = self.dns.resolve(hostname, "AAAA")

            all_ips = a_records + aaaa_records

            return {
                "verified": original_ip in all_ips,
                "ips": all_ips,
            }

        except (EngineError, EngineTimeoutError):
            return {
                "verified": False,
                "ips": [],
            }