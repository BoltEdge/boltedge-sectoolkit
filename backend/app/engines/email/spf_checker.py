"""
BoltEdge SecToolkit â€” SPF Checker Engine
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class SPFCheckerEngine:
    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def check(self, domain: str) -> dict:
        domain = validate_domain(domain)
        try:
            txt_records = self.dns.resolve(domain, "TXT")
            spf_records = [r.strip('"') for r in txt_records if r.strip('"').lower().startswith("v=spf1")]
            if not spf_records:
                return {"domain": domain, "has_spf": False, "record": None, "mechanisms": [],
                        "issues": ["No SPF record found"], "status": "missing"}
            issues = ["Multiple SPF records found â€” only one is allowed per RFC 7208"] if len(spf_records) > 1 else []
            record = spf_records[0]
            mechanisms = self._parse_mechanisms(record)
            dns_lookups = self._count_dns_lookups(mechanisms)
            issues += self._validate(record, mechanisms, dns_lookups)
            return {"domain": domain, "has_spf": True, "record": record, "record_count": len(spf_records),
                    "mechanisms": mechanisms, "dns_lookup_count": dns_lookups, "dns_lookup_limit": 10,
                    "exceeds_lookup_limit": dns_lookups > 10, "all_qualifier": self._get_all_qualifier(record),
                    "issues": issues, "status": "pass" if not issues else "warn"}
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"SPF check failed: {str(e)}")

    @staticmethod
    def _parse_mechanisms(record):
        parts = record.split()[1:]
        mechanisms = []
        for part in parts:
            qualifier = "+"
            if part[0] in "+-~?": qualifier = part[0]; part = part[1:]
            if ":" in part: mechanism, value = part.split(":", 1)
            elif "=" in part: mechanism, value = part.split("=", 1)
            else: mechanism = part; value = None
            mechanisms.append({"qualifier": qualifier,
                "qualifier_meaning": {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(qualifier, "unknown"),
                "mechanism": mechanism.lower(), "value": value,
                "raw": f"{qualifier}{part}" if qualifier != "+" else part})
        return mechanisms

    @staticmethod
    def _count_dns_lookups(mechanisms):
        return sum(1 for m in mechanisms if m["mechanism"] in {"include", "a", "mx", "ptr", "exists", "redirect"})

    @staticmethod
    def _get_all_qualifier(record):
        for part in record.lower().split():
            clean = part.lstrip("+-~?")
            if clean == "all": return part if part[0] in "+-~?" else "+all"
        return None

    @staticmethod
    def _validate(record, mechanisms, dns_lookups):
        issues = []
        if dns_lookups > 10: issues.append(f"SPF record requires {dns_lookups} DNS lookups (limit is 10)")
        if len(record) > 255: issues.append(f"SPF record is {len(record)} chars (may need splitting for DNS)")
        all_q = None
        for m in mechanisms:
            if m["mechanism"] == "all": all_q = m["qualifier"]
        if all_q == "+": issues.append("SPF uses +all â€” allows ANY server to send email (insecure)")
        if all_q == "?": issues.append("SPF uses ?all â€” neutral policy provides no protection")
        if any(m["mechanism"] == "ptr" for m in mechanisms): issues.append("SPF uses 'ptr' mechanism (deprecated per RFC 7208)")
        return issues
