"""
BoltEdge SecToolkit — Blacklist Check Engine

Tool: IP → Blacklist Check
Description: Check if IP is on email and security blacklists (DNSBLs).
Input: IPv4 address
Output: Listed/not listed per blacklist, total hits, blacklist details

Dependencies:
  - app/engines/common/dns_resolver.py
  - DNSBL queries (no API keys needed — all DNS-based)

Used by:
  - Blacklist Check tool (primary)
  - IP Reputation (DNSBL component)
  - Email → MX Check (mail server blacklist status)

How DNSBL works:
  1. Reverse the IP octets: 8.8.8.8 → 8.8.8.8
  2. Append DNSBL zone: 8.8.8.8.zen.spamhaus.org
  3. Query A record — if response exists, IP is listed
  4. Return code indicates listing category
"""
import ipaddress
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, InvalidInputError
from app.utils.validators import validate_ip


# Curated list of reliable, well-maintained DNSBLs
_DNSBL_LIST = [
    {
        "name": "Spamhaus ZEN",
        "zone": "zen.spamhaus.org",
        "type": "spam/exploit",
        "url": "https://www.spamhaus.org",
        "return_codes": {
            "127.0.0.2": "SBL (direct spam source)",
            "127.0.0.3": "SBL CSS (spam operation)",
            "127.0.0.4": "XBL (exploit/trojan)",
            "127.0.0.9": "DROP (hijacked netblock)",
            "127.0.0.10": "PBL (dynamic/residential)",
            "127.0.0.11": "PBL (ISP maintained)",
        },
    },
    {
        "name": "Barracuda",
        "zone": "b.barracudacentral.org",
        "type": "spam",
        "url": "https://www.barracudacentral.org",
        "return_codes": {
            "127.0.0.2": "Listed",
        },
    },
    {
        "name": "SpamCop",
        "zone": "bl.spamcop.net",
        "type": "spam",
        "url": "https://www.spamcop.net",
        "return_codes": {
            "127.0.0.2": "Listed (recent spam source)",
        },
    },
    {
        "name": "SORBS",
        "zone": "dnsbl.sorbs.net",
        "type": "spam/proxy",
        "url": "http://www.sorbs.net",
        "return_codes": {
            "127.0.0.2": "HTTP proxy",
            "127.0.0.3": "SOCKS proxy",
            "127.0.0.4": "Misc proxy",
            "127.0.0.5": "SMTP open relay",
            "127.0.0.6": "Spam source (recent)",
            "127.0.0.7": "Vulnerable web server",
            "127.0.0.8": "Spam source (escalated)",
            "127.0.0.9": "Zombie/botnet",
            "127.0.0.10": "Dynamic IP",
            "127.0.0.11": "Bad config (bounces)",
            "127.0.0.12": "No mail server",
            "127.0.0.14": "No MX record",
        },
    },
    {
        "name": "UCEPROTECT Level 1",
        "zone": "dnsbl-1.uceprotect.net",
        "type": "spam",
        "url": "http://www.uceprotect.net",
        "return_codes": {
            "127.0.0.2": "Listed (individual IP)",
        },
    },
    {
        "name": "Blocklist.de",
        "zone": "bl.blocklist.de",
        "type": "attacks",
        "url": "https://www.blocklist.de",
        "return_codes": {
            "127.0.0.1": "Listed (attack source)",
        },
    },
    {
        "name": "Truncate (formerly Abuseat/CBL)",
        "zone": "cbl.abuseat.org",
        "type": "exploit",
        "url": "https://www.abuseat.org",
        "return_codes": {
            "127.0.0.2": "Listed (compromised/bot)",
        },
    },
    {
        "name": "PSBL (Passive Spam Block List)",
        "zone": "psbl.surriel.com",
        "type": "spam",
        "url": "https://psbl.org",
        "return_codes": {
            "127.0.0.2": "Listed",
        },
    },
    {
        "name": "WPBL (Weighted Private Block List)",
        "zone": "db.wpbl.info",
        "type": "spam",
        "url": "http://www.wpbl.info",
        "return_codes": {
            "127.0.0.2": "Listed",
        },
    },
    {
        "name": "Suomispam Reputation",
        "zone": "bl.suomispam.net",
        "type": "spam",
        "url": "http://www.suomispam.net",
        "return_codes": {
            "127.0.0.2": "Listed",
        },
    },
]


class BlacklistCheckEngine:
    """Check IPs against DNS-based blacklists (DNSBLs)."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, ip_address: str) -> dict:
        """Check an IP against all configured DNSBLs.

        Args:
            ip_address: IPv4 address string.

        Returns:
            Dict with per-blacklist results, total listed count, and clean status.

        Raises:
            InvalidInputError: If IP is not valid or is IPv6 (most DNSBLs are IPv4 only).
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        # Most DNSBLs only support IPv4
        addr = ipaddress.ip_address(ip_address)
        if addr.version == 6:
            raise InvalidInputError("Most DNSBLs only support IPv4 addresses")

        if addr.is_private or addr.is_reserved or addr.is_loopback:
            raise InvalidInputError("Cannot check private/reserved IP addresses against blacklists")

        try:
            reversed_ip = self._reverse_ip(ip_address)
            results = []
            listed_count = 0

            for dnsbl in _DNSBL_LIST:
                check = self._check_single(reversed_ip, dnsbl)
                results.append(check)
                if check["listed"]:
                    listed_count += 1

            return {
                "ip": ip_address,
                "total_blacklists": len(_DNSBL_LIST),
                "listed_count": listed_count,
                "clean_count": len(_DNSBL_LIST) - listed_count,
                "is_clean": listed_count == 0,
                "risk_level": self._assess_risk(listed_count),
                "results": results,
            }

        except InvalidInputError:
            raise
        except Exception as e:
            raise EngineError(f"Blacklist check failed: {str(e)}")

    def _check_single(self, reversed_ip: str, dnsbl: dict) -> dict:
        """Check a single DNSBL for the reversed IP.

        Returns:
            Dict with blacklist name, listed status, return code, and reason.
        """
        query = f"{reversed_ip}.{dnsbl['zone']}"

        try:
            responses = self.dns.resolve(query, "A")

            if responses:
                return_code = responses[0]
                reason = dnsbl.get("return_codes", {}).get(return_code, "Listed")

                return {
                    "blacklist": dnsbl["name"],
                    "zone": dnsbl["zone"],
                    "type": dnsbl["type"],
                    "url": dnsbl["url"],
                    "listed": True,
                    "return_code": return_code,
                    "reason": reason,
                    "status": "listed",
                }

            return self._clean_result(dnsbl)

        except Exception:
            # NXDOMAIN or timeout means not listed (or unreachable)
            return self._clean_result(dnsbl)

    @staticmethod
    def _clean_result(dnsbl: dict) -> dict:
        """Return a clean (not listed) result for a DNSBL."""
        return {
            "blacklist": dnsbl["name"],
            "zone": dnsbl["zone"],
            "type": dnsbl["type"],
            "url": dnsbl["url"],
            "listed": False,
            "return_code": None,
            "reason": None,
            "status": "clean",
        }

    @staticmethod
    def _reverse_ip(ip_address: str) -> str:
        """Reverse IPv4 octets for DNSBL query.

        Example: "8.8.8.8" → "8.8.8.8"
        """
        return ".".join(reversed(ip_address.split(".")))

    @staticmethod
    def _assess_risk(listed_count: int) -> str:
        """Assess risk level based on number of blacklist hits."""
        if listed_count == 0:
            return "clean"
        elif listed_count <= 2:
            return "low"
        elif listed_count <= 4:
            return "medium"
        elif listed_count <= 6:
            return "high"
        else:
            return "critical"