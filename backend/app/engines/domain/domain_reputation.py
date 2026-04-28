"""
SecToolkit 101 â€” Domain Reputation Engine

Tool: Domain -> Domain Reputation
Description: Check domain against threat intel feeds.
Input: Domain name
Output: Reputation score, risk level, threat categories, feed matches
"""
from datetime import datetime, timezone
from app.utils.exceptions import EngineError, InvalidInputError
from app.utils.validators import validate_domain


_RISK_THRESHOLDS = {
    0: {"level": "clean", "score": 0},
    1: {"level": "low", "score": 25},
    2: {"level": "medium", "score": 50},
    3: {"level": "high", "score": 75},
    5: {"level": "critical", "score": 100},
}


def _calculate_risk(match_count: int) -> dict:
    result = {"level": "clean", "score": 0}
    for threshold, risk in sorted(_RISK_THRESHOLDS.items()):
        if match_count >= threshold:
            result = risk
    return result


class DomainReputationEngine:
    """Domain reputation lookup against local threat feed database."""

    def __init__(self, db=None):
        self.db = db

    def lookup(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            matches = self._query_threat_feeds(domain)
            risk = _calculate_risk(len(matches))

            return {
                "domain": domain,
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
            raise EngineError(f"Domain reputation lookup failed: {str(e)}")

    def _query_threat_feeds(self, domain: str) -> list[dict]:
        try:
            from app.models import ThreatDomain
            from app import db as app_db
            db = self.db or app_db

            records = db.session.query(ThreatDomain).filter(
                ThreatDomain.domain == domain
            ).all()

            return [
                {
                    "source": record.source,
                    "category": record.category,
                    "status": record.status,
                    "url": record.url if hasattr(record, "url") else None,
                    "first_seen": record.first_seen.isoformat() if record.first_seen else None,
                    "last_seen": record.last_seen.isoformat() if record.last_seen else None,
                }
                for record in records
            ]

        except Exception:
            return []
