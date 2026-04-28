"""
SecToolkit 101 â€” DNSSEC Validator Engine

Tool: Domain -> DNSSEC Validator
Description: Validate DNSSEC configuration.
Input: Domain name
Output: DNSSEC status, DNSKEY records, DS records, chain validation
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


class DNSSECValidatorEngine:
    """Validate DNSSEC configuration for a domain."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def validate(self, domain: str) -> dict:
        domain = validate_domain(domain)

        try:
            dnssec_data = self.dns.check_dnssec(domain)
            dnskey_details = self._parse_dnskey(dnssec_data.get("dnskey_records", []))
            ds_details = self._parse_ds(dnssec_data.get("ds_records", []))
            nsec_records = self._check_nsec(domain)
            status = self._determine_status(dnssec_data, dnskey_details, ds_details)

            return {
                "domain": domain,
                "dnssec_enabled": dnssec_data.get("enabled", False),
                "status": status,
                "dnskey": {"found": len(dnskey_details) > 0, "count": len(dnskey_details), "records": dnskey_details},
                "ds": {"found": len(ds_details) > 0, "count": len(ds_details), "records": ds_details},
                "nsec": nsec_records,
                "recommendations": self._get_recommendations(status, dnssec_data),
            }

        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"DNSSEC validation failed: {str(e)}")

    def _parse_dnskey(self, records: list[str]) -> list[dict]:
        parsed = []
        for record in records:
            parts = record.split()
            if len(parts) >= 4:
                flags = int(parts[0]) if parts[0].isdigit() else None
                protocol = int(parts[1]) if parts[1].isdigit() else None
                algorithm = int(parts[2]) if parts[2].isdigit() else None
                key_type = "unknown"
                if flags == 256: key_type = "ZSK (Zone Signing Key)"
                elif flags == 257: key_type = "KSK (Key Signing Key)"
                parsed.append({"flags": flags, "protocol": protocol, "algorithm": algorithm,
                               "algorithm_name": self._algorithm_name(algorithm), "key_type": key_type, "raw": record})
            else:
                parsed.append({"raw": record})
        return parsed

    def _parse_ds(self, records: list[str]) -> list[dict]:
        parsed = []
        for record in records:
            parts = record.split()
            if len(parts) >= 4:
                parsed.append({
                    "key_tag": int(parts[0]) if parts[0].isdigit() else None,
                    "algorithm": int(parts[1]) if parts[1].isdigit() else None,
                    "algorithm_name": self._algorithm_name(int(parts[1])) if parts[1].isdigit() else None,
                    "digest_type": int(parts[2]) if parts[2].isdigit() else None,
                    "digest_type_name": self._digest_name(int(parts[2])) if parts[2].isdigit() else None,
                    "digest": parts[3] if len(parts) > 3 else None,
                    "raw": record,
                })
            else:
                parsed.append({"raw": record})
        return parsed

    def _check_nsec(self, domain: str) -> dict:
        nsec = self._safe_resolve(domain, "NSEC")
        nsec3 = self._safe_resolve(domain, "NSEC3PARAM")
        return {
            "nsec_found": len(nsec) > 0, "nsec3_found": len(nsec3) > 0,
            "type": "NSEC3" if nsec3 else ("NSEC" if nsec else "none"),
            "records": nsec or nsec3,
        }

    def _safe_resolve(self, domain: str, record_type: str) -> list[str]:
        try:
            return self.dns.resolve(domain, record_type)
        except (EngineError, EngineTimeoutError):
            return []

    @staticmethod
    def _determine_status(dnssec_data: dict, dnskey: list, ds: list) -> str:
        has_dnskey = len(dnskey) > 0
        has_ds = len(ds) > 0
        if has_dnskey and has_ds: return "fully_signed"
        if has_dnskey and not has_ds: return "signed_no_ds (keys present but no DS in parent)"
        if not has_dnskey and has_ds: return "broken (DS in parent but no DNSKEY)"
        return "unsigned"

    @staticmethod
    def _get_recommendations(status: str, dnssec_data: dict) -> list[str]:
        r = []
        if status == "unsigned":
            r.append("Enable DNSSEC to protect against DNS spoofing and cache poisoning")
            r.append("Contact your DNS provider to enable DNSSEC signing")
        if status == "signed_no_ds":
            r.append("Add DS record to parent zone to complete DNSSEC chain of trust")
            r.append("Contact your domain registrar to publish the DS record")
        if status == "broken":
            r.append("CRITICAL: DS record exists but DNSKEY is missing - this will cause resolution failures")
            r.append("Either add DNSKEY records or remove DS from parent zone")
        return r

    @staticmethod
    def _algorithm_name(algo: int | None) -> str:
        algorithms = {
            1: "RSA/MD5 (deprecated)", 3: "DSA/SHA1", 5: "RSA/SHA-1",
            6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256",
            10: "RSA/SHA-512", 13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384",
            15: "Ed25519", 16: "Ed448",
        }
        return algorithms.get(algo, f"Unknown ({algo})")

    @staticmethod
    def _digest_name(digest_type: int | None) -> str:
        digests = {1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384"}
        return digests.get(digest_type, f"Unknown ({digest_type})")
