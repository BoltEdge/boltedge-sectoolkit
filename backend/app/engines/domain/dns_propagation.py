"""
SecToolkit 101 â€” DNS Propagation Engine

Tool: Domain -> DNS Propagation
Description: Check DNS propagation across global resolvers.
Input: Domain name, optional record type
Output: Per-resolver results showing propagation status
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


_GLOBAL_RESOLVERS = [
    {"name": "Google", "ip": "8.8.8.8", "location": "United States"},
    {"name": "Google Secondary", "ip": "8.8.4.4", "location": "United States"},
    {"name": "Cloudflare", "ip": "1.1.1.1", "location": "Global (Anycast)"},
    {"name": "Cloudflare Secondary", "ip": "1.0.0.1", "location": "Global (Anycast)"},
    {"name": "Quad9", "ip": "9.9.9.9", "location": "Global (Anycast)"},
    {"name": "OpenDNS", "ip": "208.67.222.222", "location": "United States"},
    {"name": "OpenDNS Secondary", "ip": "208.67.220.220", "location": "United States"},
    {"name": "Comodo", "ip": "8.26.56.26", "location": "United States"},
    {"name": "Level3", "ip": "4.2.2.1", "location": "United States"},
    {"name": "Verisign", "ip": "64.6.64.6", "location": "United States"},
    {"name": "CleanBrowsing", "ip": "185.228.168.9", "location": "Europe"},
    {"name": "AdGuard", "ip": "94.140.14.14", "location": "Europe"},
]


class DNSPropagationEngine:
    """Check DNS propagation across global resolvers."""

    def __init__(self):
        pass

    def check(self, domain: str, record_type: str = "A") -> dict:
        domain = validate_domain(domain)
        record_type = record_type.upper()

        try:
            results = []
            all_values = []

            for resolver in _GLOBAL_RESOLVERS:
                result = self._query_resolver(domain, record_type, resolver)
                results.append(result)
                if result["status"] == "success" and result["records"]:
                    all_values.append(frozenset(result["records"]))

            unique_answers = len(set(all_values))
            successful = [r for r in results if r["status"] == "success"]
            total_success = len(successful)

            if total_success == 0:
                propagation = 0
            elif unique_answers == 1:
                propagation = 100
            else:
                from collections import Counter
                counter = Counter(all_values)
                most_common_count = counter.most_common(1)[0][1]
                propagation = round((most_common_count / total_success) * 100)

            return {
                "domain": domain,
                "record_type": record_type,
                "propagation_percent": propagation,
                "fully_propagated": propagation == 100 and total_success > 0,
                "total_resolvers": len(_GLOBAL_RESOLVERS),
                "successful_queries": total_success,
                "unique_answers": unique_answers,
                "consistent": unique_answers <= 1,
                "results": results,
            }

        except Exception as e:
            raise EngineError(f"DNS propagation check failed: {str(e)}")

    def _query_resolver(self, domain: str, record_type: str, resolver: dict) -> dict:
        try:
            dns = DNSResolver(nameservers=[resolver["ip"]], timeout=5)
            records = dns.resolve(domain, record_type)

            return {
                "resolver": resolver["name"],
                "resolver_ip": resolver["ip"],
                "location": resolver["location"],
                "records": records,
                "status": "success",
                "error": None,
            }

        except EngineTimeoutError:
            return {
                "resolver": resolver["name"],
                "resolver_ip": resolver["ip"],
                "location": resolver["location"],
                "records": [],
                "status": "timeout",
                "error": "Query timed out",
            }

        except EngineError as e:
            return {
                "resolver": resolver["name"],
                "resolver_ip": resolver["ip"],
                "location": resolver["location"],
                "records": [],
                "status": "error",
                "error": str(e),
            }
