"""
SecToolkit 101 â€” Certificate Transparency Engine (crt.sh)
"""
import httpx
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain
from app.config import Config


class CertificateTransparencyEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def search(self, domain: str, include_subdomains: bool = True) -> dict:
        domain = validate_domain(domain)
        try:
            query = f"%.{domain}" if include_subdomains else domain
            url = f"https://crt.sh/?q={query}&output=json"
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url)
            if response.status_code != 200:
                raise EngineError(f"crt.sh returned status {response.status_code}")
            entries = response.json()
            parsed = self._parse_entries(entries)
            unique_domains = self._extract_unique_domains(parsed)
            return {
                "domain": domain, "include_subdomains": include_subdomains,
                "total_certificates": len(parsed),
                "unique_domains": sorted(unique_domains),
                "unique_domain_count": len(unique_domains),
                "certificates": parsed[:100], "source": "crt.sh",
            }
        except httpx.TimeoutException:
            raise EngineTimeoutError("crt.sh query timed out")
        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"CT log search failed: {str(e)}")

    @staticmethod
    def _parse_entries(entries: list) -> list[dict]:
        parsed = []
        seen_ids = set()
        for entry in entries:
            cert_id = entry.get("id")
            if cert_id in seen_ids: continue
            seen_ids.add(cert_id)
            parsed.append({
                "id": cert_id, "issuer": entry.get("issuer_name"),
                "common_name": entry.get("common_name"), "name_value": entry.get("name_value", ""),
                "not_before": entry.get("not_before"), "not_after": entry.get("not_after"),
                "serial_number": entry.get("serial_number"), "entry_timestamp": entry.get("entry_timestamp"),
            })
        parsed.sort(key=lambda e: e.get("not_before") or "", reverse=True)
        return parsed

    @staticmethod
    def _extract_unique_domains(entries: list[dict]) -> set[str]:
        domains = set()
        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"): domains.add(name)
                elif name.startswith("*."): domains.add(name[2:])
        return domains
