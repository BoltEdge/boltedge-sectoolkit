"""
SecToolkit 101 â€” DNS Lookup Engine

Tool: Domain -> DNS Lookup
Description: Query DNS records for any domain.
Input: Domain name
Output: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records with TTLs
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class DNSLookupEngine:
    """Query all DNS record types for a domain."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def lookup(self, domain: str, record_type: str = None) -> dict:
        domain = validate_domain(domain)

        try:
            if record_type:
                record_type = record_type.upper()
                result = self.dns.resolve_with_details(domain, record_type)
                return {
                    "domain": domain,
                    "query_type": record_type,
                    "records": {record_type: result},
                    "total_records": len(result.get("records", [])),
                }

            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
            records = {}
            total = 0

            for rtype in record_types:
                result = self.dns.resolve_with_details(domain, rtype)
                records[rtype] = result
                total += len(result.get("records", []))

            return {
                "domain": domain,
                "query_type": "ALL",
                "records": records,
                "total_records": total,
                "record_types_found": [rt for rt, data in records.items() if data.get("records")],
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"DNS lookup failed: {str(e)}")
