"""
SecToolkit 101 â€” Domain WHOIS Engine

Tool: Domain -> Domain WHOIS
Description: Query domain registration details.
Input: Domain name
Output: Registrar, registrant, dates, nameservers, status codes
"""
import whois
from datetime import datetime
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class DomainWhoisEngine:
    """Domain WHOIS lookup for registration and ownership details."""

    def lookup(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            w = whois.whois(domain)

            return {
                "domain": domain,
                "registrar": {
                    "name": self._first(w.registrar),
                    "url": self._first(w.referral_url) if hasattr(w, "referral_url") else None,
                    "whois_server": self._first(w.whois_server) if hasattr(w, "whois_server") else None,
                },
                "registrant": {
                    "name": self._first(w.name) if hasattr(w, "name") else None,
                    "organisation": self._first(w.org) if hasattr(w, "org") else None,
                    "country": self._first(w.country) if hasattr(w, "country") else None,
                    "state": self._first(w.state) if hasattr(w, "state") else None,
                    "city": self._first(w.city) if hasattr(w, "city") else None,
                },
                "dates": {
                    "created": self._format_date(w.creation_date),
                    "updated": self._format_date(w.updated_date),
                    "expires": self._format_date(w.expiration_date),
                },
                "nameservers": self._normalize_list(w.name_servers),
                "status": self._normalize_list(w.status),
                "dnssec": self._first(w.dnssec) if hasattr(w, "dnssec") else None,
                "emails": self._normalize_list(w.emails) if hasattr(w, "emails") else [],
                "registered": w.domain_name is not None,
            }

        except whois.parser.PywhoisError:
            return {
                "domain": domain,
                "registered": False,
                "registrar": None,
                "registrant": None,
                "dates": None,
                "nameservers": [],
                "status": [],
                "dnssec": None,
                "emails": [],
            }
        except Exception as e:
            raise EngineError(f"Domain WHOIS lookup failed: {str(e)}")

    @staticmethod
    def _first(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _format_date(value) -> str | None:
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            return value
        return None

    @staticmethod
    def _normalize_list(value) -> list:
        if not value:
            return []
        if isinstance(value, str):
            return [value.lower()]
        if isinstance(value, list):
            return list(set(v.lower() if isinstance(v, str) else str(v) for v in value))
        return []
