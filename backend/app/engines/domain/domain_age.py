"""
SecToolkit 101 â€” Domain Age Engine

Tool: Domain -> Domain Age
Description: Check when a domain was registered.
Input: Domain name
Output: Registration date, age in years/months/days, expiry date, registrar
"""
import whois
from datetime import datetime, timezone
from app.utils.exceptions import EngineError
from app.utils.validators import validate_domain


class DomainAgeEngine:
    """Domain age calculation from WHOIS registration data."""

    def lookup(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            w = whois.whois(domain)

            creation_date = self._extract_date(w.creation_date)
            expiration_date = self._extract_date(w.expiration_date)
            updated_date = self._extract_date(w.updated_date)

            now = datetime.now(timezone.utc)

            age = None
            age_days = None
            if creation_date:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                delta = now - creation_date
                age_days = delta.days
                age = self._format_age(delta)

            days_until_expiry = None
            if expiration_date:
                if expiration_date.tzinfo is None:
                    expiration_date = expiration_date.replace(tzinfo=timezone.utc)
                days_until_expiry = (expiration_date - now).days

            return {
                "domain": domain,
                "registered": creation_date is not None,
                "dates": {
                    "created": creation_date.isoformat() if creation_date else None,
                    "updated": updated_date.isoformat() if updated_date else None,
                    "expires": expiration_date.isoformat() if expiration_date else None,
                },
                "age": age,
                "age_days": age_days,
                "expiry": {
                    "days_until_expiry": days_until_expiry,
                    "is_expired": days_until_expiry < 0 if days_until_expiry is not None else None,
                    "expiring_soon": 0 < days_until_expiry <= 30 if days_until_expiry is not None else None,
                },
                "registrar": self._first(w.registrar),
                "trust_signal": self._assess_trust(age_days),
            }

        except whois.parser.PywhoisError:
            return {
                "domain": domain,
                "registered": False,
                "dates": None,
                "age": None,
                "age_days": None,
                "expiry": None,
                "registrar": None,
                "trust_signal": "unregistered",
            }
        except Exception as e:
            raise EngineError(f"Domain age lookup failed: {str(e)}")

    @staticmethod
    def _extract_date(value) -> datetime | None:
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, datetime):
            return value
        return None

    @staticmethod
    def _first(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _format_age(delta) -> dict:
        total_days = delta.days
        years = total_days // 365
        remaining = total_days % 365
        months = remaining // 30
        days = remaining % 30
        return {
            "years": years, "months": months, "days": days,
            "total_days": total_days,
            "human_readable": f"{years}y {months}m {days}d" if years > 0 else f"{months}m {days}d",
        }

    @staticmethod
    def _assess_trust(age_days: int | None) -> str:
        if age_days is None: return "unknown"
        if age_days < 30: return "very_new (high risk)"
        if age_days < 180: return "new (moderate risk)"
        if age_days < 365: return "established"
        if age_days < 1825: return "trusted"
        return "highly_trusted"
