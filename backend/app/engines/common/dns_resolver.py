"""
SecToolkit 101 — Shared DNS Resolver

Shared DNS helper used by multiple engines across categories:
  - IP: Reverse DNS, PTR Lookup, Blacklist Check
  - Domain: DNS Lookup, DNS Propagation, MX Records, NS Records, TXT Records,
            Subdomain Finder, DNSSEC Validator, Zone Transfer
  - Email: SPF Checker, DKIM Validator, DMARC Checker, MX Check, BIMI Check
  - Network: Status Checker

Provides a configured dnspython resolver with fallback nameservers,
timeout handling, and convenience methods for common record types.
"""
import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import dns.dnssec
import dns.name
from typing import Optional
from app.config import Config
from app.utils.exceptions import EngineError, EngineTimeoutError


class DNSResolver:
    """Configured DNS resolver with helper methods."""

    def __init__(self, nameservers: list[str] = None, timeout: int = None):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = nameservers or Config.DNS_RESOLVERS
        self.resolver.timeout = timeout or Config.DNS_TIMEOUT
        self.resolver.lifetime = (timeout or Config.DNS_TIMEOUT) * 2

    def resolve(self, domain: str, rdtype: str = "A") -> list[str]:
        """Resolve a domain for a given record type. Returns list of string values.

        Args:
            domain: The domain name to query.
            rdtype: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA).

        Returns:
            List of record values as strings.

        Raises:
            EngineTimeoutError: If the query times out.
            EngineError: If the query fails for other reasons.
        """
        try:
            answers = self.resolver.resolve(domain, rdtype)
            return [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers:
            raise EngineError(f"No nameservers available for {domain}")
        except dns.exception.Timeout:
            raise EngineTimeoutError(f"DNS query timed out for {domain} ({rdtype})")
        except dns.exception.DNSException as e:
            raise EngineError(f"DNS query failed: {str(e)}")

    def resolve_with_details(self, domain: str, rdtype: str = "A") -> dict:
        """Resolve with full metadata (TTL, nameserver, etc.).

        Returns:
            Dict with keys: records, ttl, nameserver, rdtype.
        """
        try:
            answers = self.resolver.resolve(domain, rdtype)
            return {
                "records": [str(rdata) for rdata in answers],
                "ttl": answers.rrset.ttl,
                "nameserver": answers.nameserver,
                "rdtype": rdtype,
            }
        except dns.resolver.NXDOMAIN:
            return {"records": [], "ttl": None, "nameserver": None, "rdtype": rdtype}
        except dns.resolver.NoAnswer:
            return {"records": [], "ttl": None, "nameserver": None, "rdtype": rdtype}
        except dns.exception.Timeout:
            raise EngineTimeoutError(f"DNS query timed out for {domain} ({rdtype})")
        except dns.exception.DNSException as e:
            raise EngineError(f"DNS query failed: {str(e)}")

    def reverse_lookup(self, ip_address: str) -> list[str]:
        """Perform reverse DNS lookup on an IP address.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            List of PTR record hostnames.
        """
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(rev_name, "PTR")
            return [str(rdata).rstrip(".") for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.Timeout:
            raise EngineTimeoutError(f"Reverse DNS timed out for {ip_address}")
        except dns.exception.DNSException as e:
            raise EngineError(f"Reverse DNS failed: {str(e)}")

    def resolve_all_records(self, domain: str) -> dict:
        """Resolve all common record types for a domain.

        Returns:
            Dict mapping record type to list of values.
        """
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
        results = {}

        for rdtype in record_types:
            results[rdtype] = self.resolve(domain, rdtype)

        return results

    def check_dnssec(self, domain: str) -> dict:
        """Check DNSSEC configuration for a domain.

        Returns:
            Dict with keys: enabled, valid, dnskey_records, ds_records.
        """
        result = {
            "enabled": False,
            "valid": False,
            "dnskey_records": [],
            "ds_records": [],
        }

        try:
            # Check for DNSKEY records
            dnskey = self.resolve(domain, "DNSKEY")
            result["dnskey_records"] = dnskey
            result["enabled"] = len(dnskey) > 0

            # Check for DS records
            ds = self.resolve(domain, "DS")
            result["ds_records"] = ds

            # If both exist, DNSSEC is likely valid
            if dnskey and ds:
                result["valid"] = True

        except (EngineError, EngineTimeoutError):
            pass

        return result

    def resolve_with_nameserver(self, domain: str, nameserver: str, rdtype: str = "A") -> list[str]:
        """Resolve using a specific nameserver (used for propagation checks).

        Args:
            domain: The domain name to query.
            nameserver: IP address of the nameserver to query.
            rdtype: DNS record type.

        Returns:
            List of record values as strings.
        """
        custom_resolver = dns.resolver.Resolver()
        custom_resolver.nameservers = [nameserver]
        custom_resolver.timeout = self.resolver.timeout
        custom_resolver.lifetime = self.resolver.lifetime

        try:
            answers = custom_resolver.resolve(domain, rdtype)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.Timeout:
            raise EngineTimeoutError(f"DNS query to {nameserver} timed out")
        except dns.exception.DNSException as e:
            raise EngineError(f"DNS query to {nameserver} failed: {str(e)}")

    def attempt_zone_transfer(self, domain: str) -> dict:
        """Attempt a DNS zone transfer (AXFR) on a domain.

        Returns:
            Dict with keys: vulnerable, records, nameserver.
        """
        result = {
            "vulnerable": False,
            "records": [],
            "nameserver": None,
        }

        # Get nameservers for the domain
        nameservers = self.resolve(domain, "NS")

        for ns in nameservers:
            try:
                ns_ip = self.resolve(ns, "A")
                if not ns_ip:
                    continue

                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip[0], domain, timeout=self.resolver.timeout)
                )
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append({
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "ttl": rdataset.ttl,
                                "value": str(rdata),
                            })

                result["vulnerable"] = True
                result["records"] = records
                result["nameserver"] = ns
                break  # Stop after first successful transfer

            except Exception:
                continue

        return result