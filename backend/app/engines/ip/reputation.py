"""
BoltEdge SecToolkit — IP Reputation Engine

Tool: IP → IP Reputation
Description: Check IP reputation across threat feeds.
Input: IPv4 or IPv6 address
Output: Reputation score, threat categories, feed matches, risk level

Dependencies:
  - Local threat feed database (ThreatIP model)
  - Optional: AbuseIPDB, VirusTotal, GreyNoise external APIs

Used by:
  - IP Reputation tool (primary)
  - IP Geolocation (enrichment sidebar)
  - Threat → IOC Checker (IP type)
  - Threat → Reputation Scorer (IP component)

Data sources (populated by feed_manager):
  - FireHOL blocklists (daily)
  - IPSum aggregated threat list (daily)
  - Spamhaus DROP/EDROP (daily)
  - Emerging Threats (daily)
  - Blocklist.de (daily)
  - CINS Army (daily)
  - Feodo Tracker (hourly)
"""
from datetime import datetime, timezone
from app.utils.exceptions import EngineError, InvalidInputError
from app.utils.validators import validate_ip


# Severity thresholds based on number of feed matches
_RISK_THRESHOLDS = {
    0: {"level": "clean", "score": 0},
    1: {"level": "low", "score": 25},
    2: {"level": "medium", "score": 50},
    3: {"level": "high", "score": 75},
    5: {"level": "critical", "score": 100},
}


def _calculate_risk(match_count: int) -> dict:
    """Calculate risk level and score based on number of feed matches."""
    result = {"level": "clean", "score": 0}
    for threshold, risk in sorted(_RISK_THRESHOLDS.items()):
        if match_count >= threshold:
            result = risk
    return result


class ReputationEngine:
    """IP reputation lookup against local threat feed database."""

    def __init__(self, db=None):
        """
        Args:
            db: SQLAlchemy database instance. If None, uses app context.
        """
        self.db = db

    def lookup(self, ip_address: str) -> dict:
        """Check an IP address against all local threat feeds.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Dict with reputation score, risk level, and feed matches.

        Raises:
            InvalidInputError: If IP is not valid.
            EngineError: If database query fails.
        """
        ip_address = validate_ip(ip_address)

        try:
            matches = self._query_threat_feeds(ip_address)
            risk = _calculate_risk(len(matches))

            return {
                "ip": ip_address,
                "reputation": {
                    "score": risk["score"],
                    "risk_level": risk["level"],
                    "total_matches": len(matches),
                    "is_malicious": risk["score"] >= 50,
                },
                "feeds": matches,
                "categories": list(set(m["category"] for m in matches if m.get("category"))),
                "first_seen": min((m["first_seen"] for m in matches), default=None),
                "last_seen": max((m["last_seen"] for m in matches), default=None),
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        except InvalidInputError:
            raise
        except Exception as e:
            raise EngineError(f"IP reputation lookup failed: {str(e)}")

    def _query_threat_feeds(self, ip_address: str) -> list[dict]:
        """Query local threat feed database for IP matches.

        Returns:
            List of dicts with feed match details.
        """
        try:
            from app.models import ThreatIP
            from app import db as app_db

            db = self.db or app_db

            records = db.session.query(ThreatIP).filter(
                ThreatIP.ip_address == ip_address
            ).all()

            return [
                {
                    "source": record.source,
                    "category": record.category,
                    "severity": record.severity,
                    "confidence": record.confidence,
                    "first_seen": record.first_seen.isoformat() if record.first_seen else None,
                    "last_seen": record.last_seen.isoformat() if record.last_seen else None,
                }
                for record in records
            ]

        except Exception:
            # If DB is not set up yet or table doesn't exist, return empty
            return []

    def check_private_ip(self, ip_address: str) -> dict:
        """Check if an IP is a private/reserved address.

        Returns:
            Dict with is_private flag and address type.
        """
        import ipaddress

        ip_address = validate_ip(ip_address)
        addr = ipaddress.ip_address(ip_address)

        return {
            "ip": ip_address,
            "is_private": addr.is_private,
            "is_reserved": addr.is_reserved,
            "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast,
            "is_link_local": addr.is_link_local,
            "is_global": addr.is_global,
            "version": addr.version,
            "address_type": self._get_address_type(addr),
        }

    @staticmethod
    def _get_address_type(addr) -> str:
        """Determine the address type string."""
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link-local"
        if addr.is_multicast:
            return "multicast"
        if addr.is_private:
            return "private (RFC 1918)"
        if addr.is_reserved:
            return "reserved"
        if addr.is_global:
            return "public"
        return "unknown"