"""
SecToolkit 101 — VPN Detection Engine

Tool: IP → VPN Detection
Description: Detect VPN, proxy, and Tor usage for an IP address.
Input: IPv4 or IPv6 address
Output: VPN/proxy/Tor flags, provider match, confidence score, detection methods

Dependencies:
  - Local Tor exit node list (updated hourly by feed_manager)
  - Local VPN provider IP ranges (updated daily by feed_manager)
  - MaxMind GeoLite2-ASN.mmdb (datacenter ASN detection)
  - app/engines/common/dns_resolver.py (DNSBL checks)

Used by:
  - VPN Detection tool (primary)
  - IP Reputation (VPN/proxy flag enrichment)
  - IP Geolocation (anonymiser context)
  - Threat → IOC Checker (proxy detection)

Data sources (populated by feed_manager):
  - Tor exit node list (torproject.org, hourly)
  - VPN IP ranges (github.com/X4BNet, daily)
  - Datacenter ASN list (known hosting/VPN ASNs)

Detection methods:
  1. Tor exit node list match
  2. Known VPN provider IP range match
  3. Datacenter/hosting ASN match
  4. DNS-based proxy detection (DNSBL)
  5. PTR hostname pattern analysis
"""
import ipaddress
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, InvalidInputError
from app.utils.validators import validate_ip


# Known datacenter/hosting/VPN ASNs (common anonymiser infrastructure)
# This is a subset — full list loaded from DB in production
_DATACENTER_ASNS = {
    13335: "Cloudflare",
    16509: "Amazon AWS",
    14618: "Amazon AWS",
    15169: "Google Cloud",
    8075: "Microsoft Azure",
    20473: "Vultr",
    63949: "Linode/Akamai",
    14061: "DigitalOcean",
    24940: "Hetzner",
    16276: "OVH",
    46606: "Unified Layer",
    36352: "ColoCrossing",
    55286: "Server Central",
    62563: "GTHost",
    60068: "Datacamp",
    9009: "M247 (VPN provider)",
    44592: "SkyLink (VPN infra)",
    209: "CenturyLink/Lumen",
    3223: "Voxility",
    62217: "VPN provider ASN",
    212238: "Datacamp Limited",
    51167: "Contabo",
    211298: "IVPN",
    396356: "Mullvad VPN",
    141995: "OVPN",
}

# Known VPN provider PTR patterns
_VPN_PTR_PATTERNS = [
    "nordvpn", "expressvpn", "surfshark", "cyberghost", "pia-",
    "privateinternetaccess", "mullvad", "protonvpn", "ivpn",
    "windscribe", "tunnelbear", "hotspotshield", "ipvanish",
    "vyprvpn", "strongvpn", "purevpn", "hidemyass", "hma-",
    "torguard", "astrill", "vpn-", "-vpn.", ".vpn.",
]

# Known proxy PTR patterns
_PROXY_PTR_PATTERNS = [
    "proxy", "socks", "squid", "tor-exit", "tor-relay",
    "exit-node", "anonymizer", "anon-", "crawler", "spider",
]

# DNSBL zones for proxy detection
_PROXY_DNSBLS = [
    {
        "zone": "dnsbl.tornevall.org",
        "name": "Tornevall DNSBL",
        "detects": "proxy",
    },
    {
        "zone": "all.s5h.net",
        "name": "S5H Blocklist",
        "detects": "proxy/vpn",
    },
]


class VPNDetectionEngine:
    """Detect VPN, proxy, and Tor usage for IP addresses."""

    def __init__(self, dns_resolver: DNSResolver = None, db=None):
        self.dns = dns_resolver or DNSResolver()
        self.db = db

    def detect(self, ip_address: str) -> dict:
        """Run all detection methods on an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with detection results, confidence, and matched methods.

        Raises:
            InvalidInputError: If IP is not valid.
            EngineError: If detection fails.
        """
        ip_address = validate_ip(ip_address)

        # Skip private/reserved
        addr = ipaddress.ip_address(ip_address)
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            return self._private_result(ip_address)

        try:
            checks = {
                "tor": self._check_tor(ip_address),
                "vpn_range": self._check_vpn_ranges(ip_address),
                "datacenter_asn": self._check_datacenter_asn(ip_address),
                "ptr_pattern": self._check_ptr_pattern(ip_address),
                "dnsbl_proxy": self._check_proxy_dnsbl(ip_address),
            }

            # Aggregate results
            is_tor = checks["tor"]["detected"]
            is_vpn = checks["vpn_range"]["detected"] or checks["ptr_pattern"]["vpn_detected"]
            is_proxy = checks["dnsbl_proxy"]["detected"] or checks["ptr_pattern"]["proxy_detected"]
            is_datacenter = checks["datacenter_asn"]["detected"]

            # Calculate confidence
            detections = sum([is_tor, is_vpn, is_proxy, is_datacenter])
            confidence = self._calculate_confidence(checks, detections)

            # Determine primary type
            anonymiser_type = self._determine_type(is_tor, is_vpn, is_proxy, is_datacenter)

            return {
                "ip": ip_address,
                "is_anonymiser": detections > 0,
                "anonymiser_type": anonymiser_type,
                "confidence": confidence,
                "flags": {
                    "is_tor": is_tor,
                    "is_vpn": is_vpn,
                    "is_proxy": is_proxy,
                    "is_datacenter": is_datacenter,
                },
                "detections": detections,
                "checks": checks,
                "provider": self._get_provider(checks),
            }

        except InvalidInputError:
            raise
        except Exception as e:
            raise EngineError(f"VPN detection failed: {str(e)}")

    def _check_tor(self, ip_address: str) -> dict:
        """Check against local Tor exit node list.

        Returns:
            Dict with detected flag and source.
        """
        try:
            from app.models import TorExitNode
            from app import db as app_db

            db = self.db or app_db

            node = db.session.query(TorExitNode).filter(
                TorExitNode.ip_address == ip_address
            ).first()

            if node:
                return {
                    "detected": True,
                    "method": "tor_exit_list",
                    "last_updated": node.last_updated.isoformat() if node.last_updated else None,
                }

        except Exception:
            pass

        # Fallback: DNS-based Tor check via dan.me.uk
        try:
            reversed_ip = ".".join(reversed(ip_address.split(".")))
            query = f"{reversed_ip}.dnsel.torproject.org"
            results = self.dns.resolve(query, "A")

            if results and "127.0.0.2" in results:
                return {
                    "detected": True,
                    "method": "tor_dnsel",
                    "last_updated": None,
                }

        except Exception:
            pass

        return {
            "detected": False,
            "method": None,
            "last_updated": None,
        }

    def _check_vpn_ranges(self, ip_address: str) -> dict:
        """Check against known VPN provider IP ranges.

        Returns:
            Dict with detected flag, provider, and CIDR match.
        """
        try:
            from app.models import VpnRange
            from app import db as app_db

            db = self.db or app_db
            addr = ipaddress.ip_address(ip_address)

            # Query VPN ranges that could contain this IP
            ranges = db.session.query(VpnRange).all()

            for vpn_range in ranges:
                try:
                    network = ipaddress.ip_network(vpn_range.cidr, strict=False)
                    if addr in network:
                        return {
                            "detected": True,
                            "method": "vpn_range_match",
                            "provider": vpn_range.provider,
                            "cidr": vpn_range.cidr,
                            "source": vpn_range.source,
                        }
                except ValueError:
                    continue

        except Exception:
            pass

        return {
            "detected": False,
            "method": None,
            "provider": None,
            "cidr": None,
            "source": None,
        }

    def _check_datacenter_asn(self, ip_address: str) -> dict:
        """Check if IP belongs to a known datacenter/hosting ASN.

        Returns:
            Dict with detected flag, ASN, and provider name.
        """
        try:
            import geoip2.database
            from app.config import Config

            if not Config.GEOIP_ASN_DB.exists():
                return {"detected": False, "asn": None, "provider": None, "method": None}

            reader = geoip2.database.Reader(str(Config.GEOIP_ASN_DB))
            response = reader.asn(ip_address)
            reader.close()

            asn_number = response.autonomous_system_number
            asn_org = response.autonomous_system_organization

            if asn_number in _DATACENTER_ASNS:
                return {
                    "detected": True,
                    "method": "datacenter_asn",
                    "asn": asn_number,
                    "asn_handle": f"AS{asn_number}",
                    "provider": _DATACENTER_ASNS[asn_number],
                    "organisation": asn_org,
                }

            return {
                "detected": False,
                "method": None,
                "asn": asn_number,
                "asn_handle": f"AS{asn_number}" if asn_number else None,
                "provider": None,
                "organisation": asn_org,
            }

        except Exception:
            return {
                "detected": False,
                "method": None,
                "asn": None,
                "provider": None,
                "organisation": None,
            }

    def _check_ptr_pattern(self, ip_address: str) -> dict:
        """Analyse PTR hostname for VPN/proxy patterns.

        Returns:
            Dict with VPN and proxy detection flags and matched patterns.
        """
        try:
            hostnames = self.dns.reverse_lookup(ip_address)

            if not hostnames:
                return {
                    "vpn_detected": False,
                    "proxy_detected": False,
                    "hostname": None,
                    "matched_pattern": None,
                }

            hostname = hostnames[0].lower()

            # Check VPN patterns
            for pattern in _VPN_PTR_PATTERNS:
                if pattern in hostname:
                    return {
                        "vpn_detected": True,
                        "proxy_detected": False,
                        "hostname": hostname,
                        "matched_pattern": pattern,
                    }

            # Check proxy patterns
            for pattern in _PROXY_PTR_PATTERNS:
                if pattern in hostname:
                    return {
                        "vpn_detected": False,
                        "proxy_detected": True,
                        "hostname": hostname,
                        "matched_pattern": pattern,
                    }

            return {
                "vpn_detected": False,
                "proxy_detected": False,
                "hostname": hostname,
                "matched_pattern": None,
            }

        except Exception:
            return {
                "vpn_detected": False,
                "proxy_detected": False,
                "hostname": None,
                "matched_pattern": None,
            }

    def _check_proxy_dnsbl(self, ip_address: str) -> dict:
        """Check proxy-specific DNSBLs.

        Returns:
            Dict with detected flag and matched DNSBL.
        """
        if ":" in ip_address:
            return {"detected": False, "matched_dnsbl": None}

        reversed_ip = ".".join(reversed(ip_address.split(".")))

        for dnsbl in _PROXY_DNSBLS:
            try:
                query = f"{reversed_ip}.{dnsbl['zone']}"
                results = self.dns.resolve(query, "A")

                if results:
                    return {
                        "detected": True,
                        "matched_dnsbl": dnsbl["name"],
                        "detects": dnsbl["detects"],
                    }
            except Exception:
                continue

        return {
            "detected": False,
            "matched_dnsbl": None,
        }

    @staticmethod
    def _calculate_confidence(checks: dict, detections: int) -> str:
        """Calculate overall detection confidence."""
        if detections == 0:
            return "none"

        # Tor exit list match is very high confidence
        if checks["tor"]["detected"]:
            return "very_high"

        # VPN range + datacenter ASN is high
        if checks["vpn_range"]["detected"] and checks["datacenter_asn"]["detected"]:
            return "high"

        # Single strong signal
        if checks["vpn_range"]["detected"]:
            return "high"

        if detections >= 2:
            return "medium"

        return "low"

    @staticmethod
    def _determine_type(is_tor: bool, is_vpn: bool, is_proxy: bool, is_datacenter: bool) -> str:
        """Determine the primary anonymiser type."""
        if is_tor:
            return "tor"
        if is_vpn:
            return "vpn"
        if is_proxy:
            return "proxy"
        if is_datacenter:
            return "datacenter/hosting"
        return "none"

    @staticmethod
    def _get_provider(checks: dict) -> str | None:
        """Extract the best provider name from checks."""
        if checks["vpn_range"].get("provider"):
            return checks["vpn_range"]["provider"]
        if checks["datacenter_asn"].get("provider"):
            return checks["datacenter_asn"]["provider"]
        return None

    @staticmethod
    def _private_result(ip_address: str) -> dict:
        """Return result for private/reserved IPs."""
        return {
            "ip": ip_address,
            "is_anonymiser": False,
            "anonymiser_type": "none",
            "confidence": "none",
            "flags": {
                "is_tor": False,
                "is_vpn": False,
                "is_proxy": False,
                "is_datacenter": False,
            },
            "detections": 0,
            "checks": {},
            "provider": None,
            "message": "Private/reserved IP — VPN detection not applicable",
        }