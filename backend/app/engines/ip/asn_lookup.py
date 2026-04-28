"""
SecToolkit 101 — ASN Lookup Engine

Tool: IP → ASN Lookup
Description: Lookup autonomous system information for an IP or ASN.
Input: IPv4/IPv6 address or ASN number (e.g. AS15169)
Output: ASN number, organisation, registry, prefixes, country

Dependencies:
  - MaxMind GeoLite2-ASN.mmdb (app/data/)
  - app/engines/common/dns_resolver.py (for DNS-based ASN enrichment)
  - geoip2 library

Used by:
  - ASN Lookup tool (primary)
  - IP Geolocation (ASN context)
  - VPN Detection (datacenter ASN matching)
  - IP Reputation (ASN-level reputation)
"""
import geoip2.database
import geoip2.errors
from pathlib import Path
from app.config import Config
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import (
    EngineError,
    DatabaseNotFoundError,
    InvalidInputError,
)
from app.utils.validators import validate_ip, validate_asn


class ASNLookupEngine:
    """ASN lookup using MaxMind GeoLite2 and DNS-based enrichment."""

    def __init__(self, asn_db: Path = None, dns_resolver: DNSResolver = None):
        self.asn_db_path = asn_db or Config.GEOIP_ASN_DB
        self._asn_reader = None
        self.dns = dns_resolver or DNSResolver()

    def _get_reader(self):
        """Lazy-load the GeoLite2 ASN database reader."""
        if self._asn_reader is None:
            if not self.asn_db_path.exists():
                raise DatabaseNotFoundError("GeoLite2-ASN.mmdb")
            try:
                self._asn_reader = geoip2.database.Reader(str(self.asn_db_path))
            except Exception as e:
                raise EngineError(f"Failed to open GeoLite2-ASN database: {str(e)}")
        return self._asn_reader

    def lookup_by_ip(self, ip_address: str) -> dict:
        """Lookup ASN information for an IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with ASN details and network info.

        Raises:
            InvalidInputError: If IP is not valid.
            DatabaseNotFoundError: If GeoLite2 DB is missing.
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        try:
            reader = self._get_reader()
            response = reader.asn(ip_address)

            asn_number = response.autonomous_system_number
            asn_org = response.autonomous_system_organization
            network = str(response.network) if response.network else None

            # Enrich with DNS-based TXT record from Team Cymru
            enrichment = self._cymru_enrichment(ip_address)

            return {
                "ip": ip_address,
                "asn": {
                    "number": asn_number,
                    "handle": f"AS{asn_number}" if asn_number else None,
                    "organisation": asn_org,
                    "network": network,
                    "country": enrichment.get("country"),
                    "registry": enrichment.get("registry"),
                    "allocated": enrichment.get("allocated"),
                },
            }

        except (InvalidInputError, DatabaseNotFoundError):
            raise
        except geoip2.errors.AddressNotFoundError:
            return {
                "ip": ip_address,
                "asn": {
                    "number": None,
                    "handle": None,
                    "organisation": None,
                    "network": None,
                    "country": None,
                    "registry": None,
                    "allocated": None,
                },
            }
        except Exception as e:
            raise EngineError(f"ASN lookup failed for {ip_address}: {str(e)}")

    def lookup_by_asn(self, asn: str) -> dict:
        """Lookup information for a given ASN number.

        Uses Team Cymru DNS-based lookup for ASN details.

        Args:
            asn: ASN string (e.g. "AS15169" or "15169").

        Returns:
            Dict with ASN details.

        Raises:
            InvalidInputError: If ASN format is invalid.
            EngineError: If lookup fails.
        """
        asn = validate_asn(asn)
        asn_number = asn.replace("AS", "")

        try:
            # Query Team Cymru for ASN details via DNS TXT record
            query = f"AS{asn_number}.asn.cymru.com"
            txt_records = self.dns.resolve(query, "TXT")

            if not txt_records:
                return {
                    "asn": {
                        "number": int(asn_number),
                        "handle": asn,
                        "organisation": None,
                        "country": None,
                        "registry": None,
                        "allocated": None,
                        "prefixes": [],
                    },
                }

            # Parse TXT record: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
            parsed = self._parse_cymru_asn(txt_records[0], asn_number)

            return {
                "asn": parsed,
            }

        except InvalidInputError:
            raise
        except Exception as e:
            raise EngineError(f"ASN lookup failed for {asn}: {str(e)}")

    def lookup(self, target: str) -> dict:
        """Smart lookup — detects whether input is an IP or ASN and routes accordingly.

        Args:
            target: IP address or ASN string.

        Returns:
            Dict with ASN details.
        """
        target = target.strip()

        # Check if it looks like an ASN
        if target.upper().startswith("AS") or target.isdigit():
            return self.lookup_by_asn(target)

        # Otherwise treat as IP
        return self.lookup_by_ip(target)

    def _cymru_enrichment(self, ip_address: str) -> dict:
        """Enrich IP lookup with Team Cymru DNS data.

        Queries origin.asn.cymru.com for registry and country info.

        Returns:
            Dict with country, registry, allocated fields.
        """
        try:
            # Reverse IP for Cymru query
            parts = ip_address.split(".")
            if len(parts) == 4:  # IPv4
                reversed_ip = ".".join(reversed(parts))
                query = f"{reversed_ip}.origin.asn.cymru.com"
            else:
                return {}

            txt_records = self.dns.resolve(query, "TXT")

            if not txt_records:
                return {}

            # Parse: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
            raw = txt_records[0].strip('"')
            parts = [p.strip() for p in raw.split("|")]

            if len(parts) >= 5:
                return {
                    "country": parts[2] if parts[2] else None,
                    "registry": parts[3] if parts[3] else None,
                    "allocated": parts[4] if parts[4] else None,
                }

            return {}

        except Exception:
            return {}

    def _parse_cymru_asn(self, txt_record: str, asn_number: str) -> dict:
        """Parse a Team Cymru ASN TXT record.

        Format: "15169 | US | arin | 2000-03-30 | GOOGLE, US"

        Returns:
            Formatted ASN dict.
        """
        raw = txt_record.strip('"')
        parts = [p.strip() for p in raw.split("|")]

        result = {
            "number": int(asn_number),
            "handle": f"AS{asn_number}",
            "organisation": None,
            "country": None,
            "registry": None,
            "allocated": None,
            "prefixes": [],
        }

        if len(parts) >= 1:
            result["country"] = parts[1] if len(parts) > 1 else None
            result["registry"] = parts[2] if len(parts) > 2 else None
            result["allocated"] = parts[3] if len(parts) > 3 else None
            result["organisation"] = parts[4] if len(parts) > 4 else None

        return result

    def close(self):
        """Close database reader to free resources."""
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None