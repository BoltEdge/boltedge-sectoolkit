"""
SecToolkit 101 â€” DMARC Checker Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class DMARCCheckerEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def check(self, domain: str) -> dict:
        domain = validate_domain(domain)
        try:
            txt_records = self.dns.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = [r.strip('"') for r in txt_records if "v=dmarc1" in r.lower()]
            if not dmarc_records:
                return {"domain": domain, "has_dmarc": False, "record": None, "policy": None,
                        "issues": ["No DMARC record found"], "status": "missing"}
            record = dmarc_records[0]
            parsed = self._parse_dmarc(record)
            issues = self._validate(parsed)
            return {"domain": domain, "has_dmarc": True, "record": record, "parsed": parsed,
                    "policy": parsed.get("p"), "subdomain_policy": parsed.get("sp"),
                    "aggregate_report": parsed.get("rua"), "forensic_report": parsed.get("ruf"),
                    "alignment": {"dkim": parsed.get("adkim", "r"), "spf": parsed.get("aspf", "r")},
                    "percentage": int(parsed.get("pct", 100)),
                    "issues": issues, "status": "pass" if not issues else "warn"}
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"DMARC check failed: {str(e)}")

    @staticmethod
    def _parse_dmarc(record):
        parsed = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part: key, value = part.split("=", 1); parsed[key.strip().lower()] = value.strip()
        return parsed

    @staticmethod
    def _validate(parsed):
        issues = []
        if parsed.get("p", "").lower() == "none": issues.append("DMARC policy is 'none' â€” no enforcement, monitoring only")
        if not parsed.get("rua"): issues.append("No aggregate report address (rua) â€” you won't receive DMARC reports")
        pct = int(parsed.get("pct", 100))
        if pct < 100: issues.append(f"DMARC only applies to {pct}% of messages")
        sp = parsed.get("sp")
        if sp and sp.lower() == "none" and parsed.get("p", "").lower() in ("quarantine", "reject"):
            issues.append("Subdomain policy is 'none' while main policy is stricter")
        return issues
