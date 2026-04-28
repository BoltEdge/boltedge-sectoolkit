"""
SecToolkit 101 â€” Zone Transfer Engine

Tool: Domain -> Zone Transfer
Description: Test for DNS zone transfer vulnerability.
Input: Domain name
Output: Vulnerability status, leaked records if vulnerable
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class ZoneTransferEngine:
    """Test DNS zone transfer vulnerability."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def test(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            ns_records = self.dns.resolve(domain, "NS")

            if not ns_records:
                return {
                    "domain": domain, "vulnerable": False,
                    "nameservers_tested": 0, "results": [],
                    "message": "No nameservers found for domain",
                }

            transfer_result = self.dns.attempt_zone_transfer(domain)

            ns_results = []
            for ns in ns_records:
                ns_hostname = ns.rstrip(".")
                ns_result = self._test_single_ns(domain, ns_hostname)
                ns_results.append(ns_result)

            vulnerable = transfer_result.get("vulnerable", False) or any(
                r["transfer_allowed"] for r in ns_results
            )

            all_records = transfer_result.get("records", [])
            for ns_r in ns_results:
                if ns_r["transfer_allowed"]:
                    all_records.extend(ns_r.get("records", []))

            unique_records = self._deduplicate_records(all_records)

            return {
                "domain": domain,
                "vulnerable": vulnerable,
                "severity": "high" if vulnerable else "info",
                "nameservers_tested": len(ns_results),
                "results": ns_results,
                "leaked_records": unique_records if vulnerable else [],
                "leaked_record_count": len(unique_records) if vulnerable else 0,
                "recommendation": (
                    "CRITICAL: Zone transfer is allowed. Restrict AXFR to authorised secondary nameservers only."
                    if vulnerable else "Zone transfer is properly restricted."
                ),
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"Zone transfer test failed: {str(e)}")

    def _test_single_ns(self, domain: str, nameserver: str) -> dict:
        import dns.query
        import dns.zone

        try:
            ns_ips = self.dns.resolve(nameserver, "A")
            if not ns_ips:
                return {"nameserver": nameserver, "nameserver_ip": None,
                        "transfer_allowed": False, "error": "Could not resolve nameserver IP", "records": []}

            ns_ip = ns_ips[0]

            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append({
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "ttl": rdataset.ttl,
                                "value": str(rdata),
                            })
                return {"nameserver": nameserver, "nameserver_ip": ns_ip,
                        "transfer_allowed": True, "error": None, "records": records, "record_count": len(records)}

            except dns.exception.FormError:
                return {"nameserver": nameserver, "nameserver_ip": ns_ip,
                        "transfer_allowed": False, "error": "Transfer refused", "records": []}
            except Exception:
                return {"nameserver": nameserver, "nameserver_ip": ns_ip,
                        "transfer_allowed": False, "error": "Transfer failed or refused", "records": []}

        except (EngineError, EngineTimeoutError):
            return {"nameserver": nameserver, "nameserver_ip": None,
                    "transfer_allowed": False, "error": "Could not reach nameserver", "records": []}

    @staticmethod
    def _deduplicate_records(records: list[dict]) -> list[dict]:
        seen = set()
        unique = []
        for record in records:
            key = (record.get("name"), record.get("type"), record.get("value"))
            if key not in seen:
                seen.add(key)
                unique.append(record)
        return unique
