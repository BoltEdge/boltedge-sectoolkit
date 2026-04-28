"""
SecToolkit 101 â€” Hash Lookup Engine
"""
from app.utils.exceptions import EngineError
from app.utils.validators import validate_hash, identify_hash_type


class HashLookupEngine:
    def __init__(self, db=None):
        self.db = db

    def lookup(self, hash_string: str) -> dict:
        hash_string = validate_hash(hash_string)
        hash_type = identify_hash_type(hash_string)
        threat_matches = self._query_threat_feeds(hash_string)
        return {"hash": hash_string, "hash_type": hash_type, "threat_matches": threat_matches,
                "total_matches": len(threat_matches), "is_malicious": len(threat_matches) > 0}

    def _query_threat_feeds(self, hash_string):
        try:
            from app.models import ThreatHash; from app import db as app_db
            db = self.db or app_db
            records = db.session.query(ThreatHash).filter(ThreatHash.hash_value == hash_string.lower()).all()
            return [{"source": r.source, "category": r.category,
                     "malware_name": r.malware_name if hasattr(r, "malware_name") else None,
                     "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                     "last_seen": r.last_seen.isoformat() if r.last_seen else None} for r in records]
        except Exception: return []
