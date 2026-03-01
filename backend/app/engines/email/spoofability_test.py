"""
BoltEdge SecToolkit â€” Spoofability Test Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class SpoofabilityTestEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def test(self, domain: str) -> dict:
        domain = validate_domain(domain)
        try:
            spf = self._check_spf(domain)
            dmarc = self._check_dmarc(domain)
            dkim = self._check_dkim(domain)
            score = self._calculate_score(spf, dmarc, dkim)
            return {"domain": domain, "spoofable": score["spoofable"], "risk_level": score["risk_level"],
                    "protection_score": score["score"],
                    "checks": {"spf": spf, "dmarc": dmarc, "dkim": dkim},
                    "recommendations": score["recommendations"]}
        except Exception as e: raise EngineError(f"Spoofability test failed: {str(e)}")

    def _check_spf(self, domain):
        try:
            txt = self.dns.resolve(domain, "TXT")
            spf = [r for r in txt if r.strip('"').lower().startswith("v=spf1")]
            if not spf: return {"exists": False, "record": None, "strict": False}
            record = spf[0].strip('"')
            return {"exists": True, "record": record, "strict": "-all" in record}
        except (EngineError, EngineTimeoutError): return {"exists": False, "record": None, "strict": False}

    def _check_dmarc(self, domain):
        try:
            txt = self.dns.resolve(f"_dmarc.{domain}", "TXT")
            dmarc = [r for r in txt if "v=dmarc1" in r.lower()]
            if not dmarc: return {"exists": False, "policy": None, "enforced": False}
            record = dmarc[0].strip('"'); policy = None
            for part in record.split(";"):
                if part.strip().lower().startswith("p="): policy = part.strip().split("=", 1)[1].strip().lower()
            return {"exists": True, "policy": policy, "enforced": policy in ("quarantine", "reject")}
        except (EngineError, EngineTimeoutError): return {"exists": False, "policy": None, "enforced": False}

    def _check_dkim(self, domain):
        for sel in ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]:
            try:
                txt = self.dns.resolve(f"{sel}._domainkey.{domain}", "TXT")
                if txt: return {"exists": True, "selector": sel}
            except (EngineError, EngineTimeoutError): continue
        return {"exists": False, "selector": None}

    @staticmethod
    def _calculate_score(spf, dmarc, dkim):
        score = 0; recommendations = []
        if spf["exists"]:
            score += 25
            if spf["strict"]: score += 10
            else: recommendations.append("Tighten SPF to use -all instead of ~all")
        else: recommendations.append("Add SPF record to prevent spoofing")
        if dmarc["exists"]:
            score += 25
            if dmarc["enforced"]: score += 20
            else: recommendations.append("Set DMARC policy to quarantine or reject")
        else: recommendations.append("Add DMARC record with enforcement policy")
        if dkim["exists"]: score += 20
        else: recommendations.append("Configure DKIM signing for outbound email")
        spoofable = score < 50
        if score >= 80: risk = "low"
        elif score >= 50: risk = "medium"
        elif score >= 25: risk = "high"
        else: risk = "critical"
        return {"score": score, "spoofable": spoofable, "risk_level": risk, "recommendations": recommendations}
