"""
BoltEdge SecToolkit — IP WHOIS Engine

Tool: IP → IP WHOIS
Description: Query IP registration and ownership details.
Input: IPv4 or IPv6 address
Output: Network range, organisation, registrar, abuse contact, registration dates

Dependencies:
  - ipwhois library (RDAP + legacy WHOIS fallback)

Used by:
  - IP WHOIS tool (primary)
  - IP Geolocation (enrichment)
  - IP Reputation (context)
  - Domain → Reverse IP (IP ownership context)
"""
from ipwhois import IPWhois
from ipwhois.exceptions import (
    IPDefinedError,
    ASNRegistryError,
    WhoisLookupError,
    HTTPLookupError,
)
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_ip
from app.config import Config


class WhoisEngine:
    """IP WHOIS lookup using RDAP with legacy WHOIS fallback."""

    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.DEFAULT_TIMEOUT

    def lookup(self, ip_address: str) -> dict:
        """Perform WHOIS lookup for an IP address.

        Tries RDAP first (modern, structured), falls back to legacy WHOIS.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with registration, network, and organisation details.

        Raises:
            InvalidInputError: If IP is not valid.
            EngineError: If lookup fails.
        """
        ip_address = validate_ip(ip_address)

        # Check for private/reserved IPs
        import ipaddress
        addr = ipaddress.ip_address(ip_address)
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            return {
                "ip": ip_address,
                "type": "private" if addr.is_private else "reserved",
                "message": "WHOIS data is not available for private/reserved addresses",
                "network": None,
                "organisation": None,
                "registrar": None,
                "abuse_contact": None,
                "dates": None,
                "raw": None,
            }

        # Try RDAP first, fallback to legacy WHOIS
        try:
            return self._rdap_lookup(ip_address)
        except EngineError:
            try:
                return self._legacy_lookup(ip_address)
            except EngineError:
                raise EngineError(f"WHOIS lookup failed for {ip_address} (both RDAP and legacy)")

    def _rdap_lookup(self, ip_address: str) -> dict:
        """Perform RDAP lookup (modern, structured data).

        Returns:
            Formatted WHOIS result dict.
        """
        try:
            obj = IPWhois(ip_address)
            response = obj.lookup_rdap(asn_methods=["whois", "dns", "http"], timeout=self.timeout)

            return self._format_rdap(ip_address, response)

        except IPDefinedError:
            raise InvalidInputError(f"IP is a private/reserved address: {ip_address}")
        except (ASNRegistryError, HTTPLookupError, WhoisLookupError) as e:
            raise EngineError(f"RDAP lookup failed: {str(e)}")
        except TimeoutError:
            raise EngineTimeoutError(f"RDAP lookup timed out for {ip_address}")
        except Exception as e:
            raise EngineError(f"RDAP lookup failed: {str(e)}")

    def _legacy_lookup(self, ip_address: str) -> dict:
        """Perform legacy WHOIS lookup (fallback).

        Returns:
            Formatted WHOIS result dict.
        """
        try:
            obj = IPWhois(ip_address)
            response = obj.lookup_whois(asn_methods=["whois", "dns", "http"])

            return self._format_legacy(ip_address, response)

        except IPDefinedError:
            raise InvalidInputError(f"IP is a private/reserved address: {ip_address}")
        except (ASNRegistryError, WhoisLookupError) as e:
            raise EngineError(f"Legacy WHOIS lookup failed: {str(e)}")
        except TimeoutError:
            raise EngineTimeoutError(f"WHOIS lookup timed out for {ip_address}")
        except Exception as e:
            raise EngineError(f"Legacy WHOIS lookup failed: {str(e)}")

    def _format_rdap(self, ip_address: str, response: dict) -> dict:
        """Format RDAP response into standard output."""
        # Extract network info
        network = response.get("network", {}) or {}

        # Extract the best entity for organisation and abuse contact
        org_name = None
        abuse_email = None
        entities = response.get("objects", {}) or {}

        for entity_key, entity in entities.items():
            roles = entity.get("roles", [])
            contact = entity.get("contact", {}) or {}

            if "registrant" in roles or "administrative" in roles:
                org_name = org_name or contact.get("name")

            if "abuse" in roles:
                abuse_email = self._extract_email(contact)

            # Fallback: grab name from any entity
            if not org_name:
                org_name = contact.get("name")

        return {
            "ip": ip_address,
            "type": "rdap",
            "network": {
                "cidr": network.get("cidr"),
                "name": network.get("name"),
                "handle": network.get("handle"),
                "range": f"{network.get('start_address', '')} - {network.get('end_address', '')}",
                "parent_handle": network.get("parent_handle"),
                "ip_version": network.get("ip_version"),
                "type": network.get("type"),
                "country": network.get("country"),
            },
            "organisation": {
                "name": org_name,
            },
            "registrar": {
                "name": network.get("name"),
            },
            "abuse_contact": {
                "email": abuse_email,
            },
            "asn": {
                "number": response.get("asn"),
                "name": response.get("asn_description"),
                "registry": response.get("asn_registry"),
                "cidr": response.get("asn_cidr"),
                "country": response.get("asn_country_code"),
            },
            "dates": {
                "created": self._safe_list_first(network.get("events", []), "action", "registration"),
                "updated": self._safe_list_first(network.get("events", []), "action", "last changed"),
            },
            "raw": None,  # Omit raw to keep response clean
        }

    def _format_legacy(self, ip_address: str, response: dict) -> dict:
        """Format legacy WHOIS response into standard output."""
        nets = response.get("nets", []) or []
        primary_net = nets[0] if nets else {}

        return {
            "ip": ip_address,
            "type": "whois",
            "network": {
                "cidr": primary_net.get("cidr"),
                "name": primary_net.get("name"),
                "handle": primary_net.get("handle"),
                "range": primary_net.get("range"),
                "parent_handle": None,
                "ip_version": None,
                "type": None,
                "country": primary_net.get("country"),
            },
            "organisation": {
                "name": primary_net.get("description"),
            },
            "registrar": {
                "name": primary_net.get("name"),
            },
            "abuse_contact": {
                "email": primary_net.get("abuse_emails") if isinstance(primary_net.get("abuse_emails"), str) else (
                    primary_net.get("abuse_emails", [None])[0] if primary_net.get("abuse_emails") else None
                ),
            },
            "asn": {
                "number": response.get("asn"),
                "name": response.get("asn_description"),
                "registry": response.get("asn_registry"),
                "cidr": response.get("asn_cidr"),
                "country": response.get("asn_country_code"),
            },
            "dates": {
                "created": primary_net.get("created"),
                "updated": primary_net.get("updated"),
            },
            "raw": None,
        }

    @staticmethod
    def _extract_email(contact: dict) -> str | None:
        """Extract email from an RDAP contact object."""
        emails = contact.get("email", [])
        if isinstance(emails, list) and emails:
            return emails[0].get("value") if isinstance(emails[0], dict) else emails[0]
        if isinstance(emails, str):
            return emails
        return None

    @staticmethod
    def _safe_list_first(events: list, key: str, value: str) -> str | None:
        """Find first event matching key=value and return its timestamp."""
        if not events:
            return None
        for event in events:
            if isinstance(event, dict) and event.get(key) == value:
                return event.get("timestamp")
        return None