"""
SecToolkit 101 â€” URL Reputation Engine
"""
from datetime import datetime, timezone
from urllib.parse import urlparse
from app.utils.exceptions import EngineError
from app.utils.validators import validate_url


class URLReputationEngine:
    def __init__(self, db=None):
        self.db = db

    def lookup(self, url: str) -> dict:
        url = validate_url(url)
        parsed = urlparse(url)
        domain = parsed.hostname
        try:
            url_matches = self._query_url_feeds(url)
            domain_matches = self._query_domain_feeds(domain) if domain else []
            total = len(url_matches) + len(domain_matches)
            risk = self._calculate_risk(total)
            return {"url": url, "domain": domain, "reputation": {"score": risk["score"], "risk_level": risk["level"],
                    "total_matches": total, "is_malicious": risk["score"] >= 50},
                    "url_matches": url_matches, "domain_matches": domain_matches,
                    "checked_at": datetime.now(timezone.utc).isoformat()}
        except Exception as e: raise EngineError(f"URL reputation lookup failed: {str(e)}")

    def _query_url_feeds(self, url):
        try:
            from app.models import ThreatURL; from app import db as app_db
            db = self.db or app_db
            records = db.session.query(ThreatURL).filter(ThreatURL.url == url).all()
            return [{"source": r.source, "category": r.category, "status": r.status,
                     "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                     "last_seen": r.last_seen.isoformat() if r.last_seen else None} for r in records]
        except Exception: return []

    def _query_domain_feeds(self, domain):
        try:
            from app.models import ThreatDomain; from app import db as app_db
            db = self.db or app_db
            records = db.session.query(ThreatDomain).filter(ThreatDomain.domain == domain).all()
            return [{"source": r.source, "category": r.category, "match_type": "domain"} for r in records]
        except Exception: return []

    @staticmethod
    def _calculate_risk(m):
        if m == 0: return {"level": "clean", "score": 0}
        if m == 1: return {"level": "low", "score": 25}
        if m == 2: return {"level": "medium", "score": 50}
        if m <= 4: return {"level": "high", "score": 75}
        return {"level": "critical", "score": 100}
