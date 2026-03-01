"""
BoltEdge SecToolkit — IP History Engine

Tool: IP → IP History
Description: View historical DNS records for an IP address.
Input: IPv4 or IPv6 address
Output: Current PTR/reverse DNS, associated domains, timeline of changes

Dependencies:
  - app/engines/common/dns_resolver.py
  - Local lookup history database (LookupHistory model)
  - Optional: SecurityTrails, PassiveTotal external APIs (future)

Used by:
  - IP History tool (primary)
  - IP Reputation (historical context)
  - Threat → IOC Checker (IP history enrichment)

Note: Full passive DNS history requires external data sources (SecurityTrails,
      PassiveTotal, etc.) which will be added as services later.
      For now, this engine provides:
        1. Current reverse DNS state
        2. Local lookup history from our own database
        3. Basic infrastructure fingerprinting
"""
from datetime import datetime, timezone
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_ip


class IPHistoryEngine:
    """IP history lookup combining current DNS state and local history."""

    def __init__(self, dns_resolver: DNSResolver = None, db=None):
        self.dns = dns_resolver or DNSResolver()
        self.db = db

    def lookup(self, ip_address: str) -> dict:
        """Retrieve historical information for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with current DNS state, local history, and infrastructure info.

        Raises:
            InvalidInputError: If IP is not valid.
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        try:
            current_dns = self._get_current_dns(ip_address)
            local_history = self._get_local_history(ip_address)
            infrastructure = self._fingerprint_infrastructure(ip_address, current_dns)

            return {
                "ip": ip_address,
                "current_dns": current_dns,
                "local_history": local_history,
                "infrastructure": infrastructure,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"IP history lookup failed: {str(e)}")

    def _get_current_dns(self, ip_address: str) -> dict:
        """Get current reverse DNS and associated records.

        Returns:
            Dict with PTR records and forward-verified hostnames.
        """
        try:
            ptr_records = self.dns.reverse_lookup(ip_address)

            # For each PTR, resolve forward to see what IPs the hostname points to
            associated_domains = []
            for hostname in ptr_records:
                try:
                    a_records = self.dns.resolve(hostname, "A")
                    aaaa_records = self.dns.resolve(hostname, "AAAA")
                    associated_domains.append({
                        "hostname": hostname,
                        "a_records": a_records,
                        "aaaa_records": aaaa_records,
                        "points_back": ip_address in a_records + aaaa_records,
                    })
                except (EngineError, EngineTimeoutError):
                    associated_domains.append({
                        "hostname": hostname,
                        "a_records": [],
                        "aaaa_records": [],
                        "points_back": False,
                    })

            return {
                "ptr_records": ptr_records,
                "associated_domains": associated_domains,
                "has_ptr": len(ptr_records) > 0,
            }

        except (EngineError, EngineTimeoutError):
            return {
                "ptr_records": [],
                "associated_domains": [],
                "has_ptr": False,
            }

    def _get_local_history(self, ip_address: str) -> dict:
        """Query local lookup history database for previous lookups of this IP.

        Returns:
            Dict with previous lookups, tools used, and date range.
        """
        try:
            from app.models import LookupHistory
            from app import db as app_db

            db = self.db or app_db

            records = db.session.query(LookupHistory).filter(
                LookupHistory.target == ip_address
            ).order_by(
                LookupHistory.created_at.desc()
            ).limit(50).all()

            if not records:
                return {
                    "total_lookups": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "tools_used": [],
                    "entries": [],
                }

            entries = [
                {
                    "tool": record.tool,
                    "timestamp": record.created_at.isoformat() if record.created_at else None,
                    "source": record.source,
                    "duration_ms": record.duration_ms,
                }
                for record in records
            ]

            tools_used = list(set(e["tool"] for e in entries))

            return {
                "total_lookups": len(entries),
                "first_seen": entries[-1]["timestamp"] if entries else None,
                "last_seen": entries[0]["timestamp"] if entries else None,
                "tools_used": tools_used,
                "entries": entries,
            }

        except Exception:
            # DB not set up yet or table doesn't exist
            return {
                "total_lookups": 0,
                "first_seen": None,
                "last_seen": None,
                "tools_used": [],
                "entries": [],
            }

    def _fingerprint_infrastructure(self, ip_address: str, current_dns: dict) -> dict:
        """Basic infrastructure fingerprinting based on PTR patterns.

        Analyses PTR hostnames to infer hosting provider, type, etc.

        Returns:
            Dict with inferred provider, type, and confidence.
        """
        ptr_records = current_dns.get("ptr_records", [])

        if not ptr_records:
            return {
                "provider": None,
                "type": None,
                "confidence": "none",
            }

        hostname = ptr_records[0].lower()

        # Common provider patterns
        providers = {
            "amazonaws.com": ("AWS", "cloud"),
            "googleusercontent.com": ("Google Cloud", "cloud"),
            "compute.google": ("Google Cloud", "cloud"),
            "azure.com": ("Microsoft Azure", "cloud"),
            "cloudfront.net": ("AWS CloudFront", "cdn"),
            "akamai": ("Akamai", "cdn"),
            "cloudflare": ("Cloudflare", "cdn/proxy"),
            "fastly": ("Fastly", "cdn"),
            "digitalocean.com": ("DigitalOcean", "cloud"),
            "linode.com": ("Linode/Akamai", "cloud"),
            "vultr.com": ("Vultr", "cloud"),
            "hetzner": ("Hetzner", "hosting"),
            "ovh.": ("OVH", "hosting"),
            "rackspace": ("Rackspace", "cloud"),
            "comcast": ("Comcast", "residential ISP"),
            "verizon": ("Verizon", "residential ISP"),
            "att.net": ("AT&T", "residential ISP"),
            "charter.com": ("Spectrum", "residential ISP"),
            "cox.net": ("Cox", "residential ISP"),
            "telstra": ("Telstra", "residential ISP"),
            "optusnet": ("Optus", "residential ISP"),
        }

        for pattern, (provider, infra_type) in providers.items():
            if pattern in hostname:
                return {
                    "provider": provider,
                    "type": infra_type,
                    "confidence": "high",
                    "matched_pattern": pattern,
                    "hostname": hostname,
                }

        # Check for common dynamic/residential patterns
        dynamic_patterns = ["dsl", "dhcp", "dynamic", "pool", "dial", "ppp", "cable", "broadband"]
        for pattern in dynamic_patterns:
            if pattern in hostname:
                return {
                    "provider": None,
                    "type": "residential/dynamic",
                    "confidence": "medium",
                    "matched_pattern": pattern,
                    "hostname": hostname,
                }

        return {
            "provider": None,
            "type": "unknown",
            "confidence": "low",
            "matched_pattern": None,
            "hostname": hostname,
        }