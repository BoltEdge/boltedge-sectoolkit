"""
SecToolkit 101 â€” Threat Intel Engines (7 tools)
"""
from datetime import datetime, timezone
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_ip, validate_domain
import ipaddress, re, json


# 1. IOC Checker
class IOCCheckerEngine:
    def __init__(self, db=None):
        self.db = db

    def check(self, ioc):
        ioc = ioc.strip(); ioc_type = self._detect_type(ioc)
        matches = self._query_feeds(ioc, ioc_type); risk = self._score(len(matches))
        return {"ioc": ioc, "type": ioc_type, "risk_level": risk["level"], "risk_score": risk["score"],
                "is_malicious": risk["score"] >= 50, "total_matches": len(matches), "matches": matches,
                "checked_at": datetime.now(timezone.utc).isoformat()}

    def _detect_type(self, ioc):
        try: ipaddress.ip_address(ioc); return "ip"
        except ValueError: pass
        if re.match(r"^[a-fA-F0-9]{32,128}$", ioc): return "hash"
        if ioc.startswith(("http://", "https://")): return "url"
        if "." in ioc and not ioc.startswith("/"): return "domain"
        return "unknown"

    def _query_feeds(self, ioc, ioc_type):
        try:
            from app import db as app_db; db = self.db or app_db
            if ioc_type == "ip":
                from app.models import ThreatIP; records = db.session.query(ThreatIP).filter(ThreatIP.ip == ioc).all()
            elif ioc_type == "domain":
                from app.models import ThreatDomain; records = db.session.query(ThreatDomain).filter(ThreatDomain.domain == ioc).all()
            elif ioc_type == "hash":
                from app.models import ThreatHash; records = db.session.query(ThreatHash).filter(ThreatHash.hash_value == ioc.lower()).all()
            else: return []
            return [{"source": r.source, "category": r.category} for r in records]
        except Exception: return []

    @staticmethod
    def _score(m):
        if m == 0: return {"level": "clean", "score": 0}
        if m == 1: return {"level": "low", "score": 25}
        if m <= 3: return {"level": "medium", "score": 50}
        if m <= 5: return {"level": "high", "score": 75}
        return {"level": "critical", "score": 100}


# 2. Reputation Scorer
class ReputationScorerEngine:
    def __init__(self, dns_resolver=None, db=None):
        self.dns = dns_resolver or DNSResolver(); self.db = db; self.ioc = IOCCheckerEngine(db=db)

    def score(self, target):
        ioc_result = self.ioc.check(target); ioc_type = ioc_result["type"]
        signals = [{"name": "threat_feeds", "score": ioc_result["risk_score"], "weight": 0.6}]
        if ioc_type in ("ip", "domain"):
            signals.append({"name": "dnsbl", "score": self._check_dnsbl(target, ioc_type), "weight": 0.4})
        weighted = sum(s["score"] * s["weight"] for s in signals)
        total_weight = sum(s["weight"] for s in signals)
        final = round(weighted / total_weight) if total_weight > 0 else 0
        level = "critical" if final >= 75 else ("high" if final >= 50 else ("medium" if final >= 25 else ("low" if final > 0 else "clean")))
        return {"target": target, "type": ioc_type, "reputation_score": final,
                "risk_level": level, "signals": signals, "ioc_matches": ioc_result["total_matches"]}

    def _check_dnsbl(self, target, ioc_type):
        if ioc_type == "ip":
            try:
                reversed_ip = ".".join(reversed(target.split(".")))
                result = self.dns.resolve(f"{reversed_ip}.zen.spamhaus.org", "A")
                return 75 if result else 0
            except Exception: return 0
        return 0


# 3. CVE Lookup
class CVELookupEngine:
    def __init__(self, db=None):
        self.db = db

    def lookup(self, cve_id):
        cve_id = cve_id.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            raise InvalidInputError(f"Invalid CVE ID format: {cve_id}")
        record = self._query_local(cve_id)
        if record: return record
        return {"cve_id": cve_id, "found": False, "message": "CVE not found in local database. External API integration pending.",
                "nist_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "mitre_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"}

    def _query_local(self, cve_id):
        try:
            from app.models import CVE; from app import db as app_db; db = self.db or app_db
            r = db.session.query(CVE).filter(CVE.cve_id == cve_id).first()
            if r: return {"cve_id": r.cve_id, "found": True, "description": r.description,
                          "severity": r.severity, "cvss_score": r.cvss_score,
                          "published": r.published.isoformat() if r.published else None}
        except Exception: pass
        return None


# 4. Exploit Search
class ExploitSearchEngine:
    def __init__(self, db=None):
        self.db = db

    def search(self, query):
        if not query or not query.strip(): raise InvalidInputError("Search query is required")
        results = self._query_local(query.strip())
        return {"query": query, "total_results": len(results), "results": results,
                "note": "External exploit-db integration pending."}

    def _query_local(self, query):
        try:
            from app.models import Exploit; from app import db as app_db; db = self.db or app_db
            records = db.session.query(Exploit).filter(Exploit.title.ilike(f"%{query}%")).limit(50).all()
            return [{"id": r.id, "title": r.title, "platform": r.platform, "type": r.exploit_type} for r in records]
        except Exception: return []


# 5. Threat Feed Status
class ThreatFeedStatusEngine:
    def __init__(self, db=None):
        self.db = db

    def status(self):
        feeds = [{"name": "FireHOL Level 1", "type": "ip", "source": "firehol"},
                 {"name": "IPSum Level 3+", "type": "ip", "source": "ipsum"},
                 {"name": "Spamhaus DROP", "type": "ip", "source": "spamhaus_drop"},
                 {"name": "URLhaus", "type": "domain", "source": "urlhaus"},
                 {"name": "PhishTank", "type": "domain", "source": "phishtank"},
                 {"name": "MalwareBazaar", "type": "hash", "source": "malwarebazaar"}]
        feed_status = [{"name": f["name"], "type": f["type"],
                        "entries": self._count(f["type"], f["source"]),
                        "status": "active" if self._count(f["type"], f["source"]) > 0 else "empty"} for f in feeds]
        return {"feeds": feed_status, "total_feeds": len(feed_status),
                "active_feeds": sum(1 for f in feed_status if f["status"] == "active"),
                "checked_at": datetime.now(timezone.utc).isoformat()}

    def _count(self, feed_type, source):
        try:
            from app import db as app_db; db = self.db or app_db
            if feed_type == "ip":
                from app.models import ThreatIP; return db.session.query(ThreatIP).filter(ThreatIP.source == source).count()
            elif feed_type == "domain":
                from app.models import ThreatDomain; return db.session.query(ThreatDomain).filter(ThreatDomain.source == source).count()
            elif feed_type == "hash":
                from app.models import ThreatHash; return db.session.query(ThreatHash).filter(ThreatHash.source == source).count()
        except Exception: pass
        return 0


# 6. STIX Viewer
class STIXViewerEngine:
    def parse(self, stix_json):
        if not stix_json: raise InvalidInputError("Empty STIX data")
        try: data = json.loads(stix_json) if isinstance(stix_json, str) else stix_json
        except json.JSONDecodeError as e: raise InvalidInputError(f"Invalid JSON: {str(e)}")
        if data.get("type") == "bundle":
            objects = data.get("objects", [])
            counts = {}
            for obj in objects: t = obj.get("type", "unknown"); counts[t] = counts.get(t, 0) + 1
            return {"type": "bundle", "id": data.get("id"), "spec_version": data.get("spec_version"),
                    "total_objects": len(objects), "object_types": counts, "objects": objects[:50]}
        return {"type": data.get("type"), "id": data.get("id"), "name": data.get("name"),
                "description": data.get("description"), "created": data.get("created"),
                "modified": data.get("modified"), "labels": data.get("labels", []), "raw": data}


# 7. Abuse Contact Finder
class AbuseContactFinderEngine:
    def __init__(self, dns_resolver=None):
        self.dns = dns_resolver or DNSResolver()

    def find(self, target):
        target = target.strip()
        try: validate_ip(target); return self._find_ip(target)
        except InvalidInputError: pass
        try: domain = validate_domain(target); return self._find_domain(domain)
        except InvalidInputError: raise InvalidInputError(f"Not a valid IP or domain: {target}")

    def _find_ip(self, ip):
        contacts = []
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            txt = self.dns.resolve(f"{reversed_ip}.abuse-contacts.abusix.org", "TXT")
            if txt: contacts.append({"source": "Abusix", "contact": txt[0].strip('"')})
        except (EngineError, EngineTimeoutError): pass
        return {"target": ip, "type": "ip", "contacts": contacts, "total_contacts": len(contacts)}

    def _find_domain(self, domain):
        contacts = [{"source": "Convention", "contact": f"abuse@{domain}"}]
        try:
            soa = self.dns.resolve(domain, "SOA")
            if soa:
                parts = soa[0].split()
                if len(parts) >= 2: contacts.append({"source": "SOA RNAME", "contact": parts[1].replace(".", "@", 1).rstrip(".")})
        except (EngineError, EngineTimeoutError): pass
        return {"target": domain, "type": "domain", "contacts": contacts, "total_contacts": len(contacts)}
