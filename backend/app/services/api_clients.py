"""
SecToolkit 101 - External API Clients

Shared API client classes for external threat intelligence services.
All clients are optional - engines gracefully degrade if API keys are missing.

Usage in engines:
    from app.services.api_clients import VirusTotalClient
    vt = VirusTotalClient()
    if vt.available:
        result = vt.check_ip("8.8.8.8")
"""
import httpx
import hashlib
import time
from app.config import Config
from app.utils.exceptions import ExternalServiceError, EngineTimeoutError


# ============================================================
# Base Client
# ============================================================

class BaseAPIClient:
    """Base class for all external API clients."""

    SERVICE_NAME = "Unknown"
    BASE_URL = ""
    REQUIRED_KEY = ""

    def __init__(self, api_key=None, timeout=None):
        self.api_key = api_key or getattr(Config, self.REQUIRED_KEY, "")
        self.timeout = timeout or Config.HTTP_TIMEOUT
        self._client = None

    @property
    def available(self):
        return bool(self.api_key)

    def _get_client(self):
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.BASE_URL,
                timeout=self.timeout,
                headers=self._default_headers(),
            )
        return self._client

    def _default_headers(self):
        return {"User-Agent": Config.USER_AGENT}

    def _request(self, method, path, **kwargs):
        if not self.available:
            return {"error": self.SERVICE_NAME + " API key not configured", "available": False}
        try:
            client = self._get_client()
            response = client.request(method, path, **kwargs)
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                raise ExternalServiceError(self.SERVICE_NAME, "Rate limited. Retry after " + str(retry_after) + "s")
            if response.status_code == 401:
                raise ExternalServiceError(self.SERVICE_NAME, "Invalid API key")
            if response.status_code == 403:
                raise ExternalServiceError(self.SERVICE_NAME, "Access forbidden - check API key permissions")
            if response.status_code >= 400:
                raise ExternalServiceError(self.SERVICE_NAME, "HTTP " + str(response.status_code) + ": " + response.text[:200])
            return response.json()
        except httpx.TimeoutException:
            raise EngineTimeoutError(self.SERVICE_NAME + " request timed out")
        except (ExternalServiceError, EngineTimeoutError):
            raise
        except Exception as e:
            raise ExternalServiceError(self.SERVICE_NAME, str(e))

    def close(self):
        if self._client:
            self._client.close()
            self._client = None


# ============================================================
# VirusTotal (v3 API)
# ============================================================

class VirusTotalClient(BaseAPIClient):
    SERVICE_NAME = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"
    REQUIRED_KEY = "VIRUSTOTAL_API_KEY"

    def _default_headers(self):
        return {"x-apikey": self.api_key, "User-Agent": Config.USER_AGENT}

    def check_ip(self, ip):
        data = self._request("GET", "/ip_addresses/" + ip)
        if "error" in data and not data.get("available", True):
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal", "ip": ip,
            "reputation": attrs.get("reputation", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "asn": attrs.get("asn"),
            "network": attrs.get("network"),
            "whois": (attrs.get("whois", "") or "")[:500],
        }

    def check_domain(self, domain):
        data = self._request("GET", "/domains/" + domain)
        if "error" in data and not data.get("available", True):
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal", "domain": domain,
            "reputation": attrs.get("reputation", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "categories": attrs.get("categories", {}),
        }

    def check_hash(self, file_hash):
        data = self._request("GET", "/files/" + file_hash)
        if "error" in data and not data.get("available", True):
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        threat_class = attrs.get("popular_threat_classification", {})
        return {
            "source": "virustotal", "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "type_description": attrs.get("type_description"),
            "type_tag": attrs.get("type_tag"),
            "size": attrs.get("size"),
            "names": (attrs.get("names", []) or [])[:10],
            "popular_threat_name": threat_class.get("suggested_threat_label"),
            "sha256": attrs.get("sha256"),
            "md5": attrs.get("md5"),
            "sha1": attrs.get("sha1"),
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "tags": (attrs.get("tags", []) or [])[:20],
        }

    def check_url(self, url):
        url_id = hashlib.sha256(url.encode()).hexdigest()
        data = self._request("GET", "/urls/" + url_id)
        if "error" in data and not data.get("available", True):
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal", "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "categories": attrs.get("categories", {}),
        }


# ============================================================
# AbuseIPDB (v2 API)
# ============================================================

class AbuseIPDBClient(BaseAPIClient):
    SERVICE_NAME = "AbuseIPDB"
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    REQUIRED_KEY = "ABUSEIPDB_API_KEY"

    def _default_headers(self):
        return {"Key": self.api_key, "Accept": "application/json", "User-Agent": Config.USER_AGENT}

    def check_ip(self, ip, max_age_days=90):
        data = self._request("GET", "/check", params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""})
        if "error" in data and not data.get("available", True):
            return data
        result = data.get("data", {})
        reports = result.get("reports", [])
        first_report_cats = reports[0].get("categories", []) if reports else []
        return {
            "source": "abuseipdb", "ip": ip,
            "is_public": result.get("isPublic"),
            "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
            "total_reports": result.get("totalReports", 0),
            "num_distinct_users": result.get("numDistinctUsers", 0),
            "country_code": result.get("countryCode"),
            "isp": result.get("isp"),
            "domain": result.get("domain"),
            "usage_type": result.get("usageType"),
            "is_tor": result.get("isTor", False),
            "is_whitelisted": result.get("isWhitelisted"),
            "last_reported_at": result.get("lastReportedAt"),
            "categories": first_report_cats,
        }


# ============================================================
# Shodan
# ============================================================

class ShodanClient(BaseAPIClient):
    SERVICE_NAME = "Shodan"
    BASE_URL = "https://api.shodan.io"
    REQUIRED_KEY = "SHODAN_API_KEY"

    def check_ip(self, ip):
        data = self._request("GET", "/shodan/host/" + ip, params={"key": self.api_key})
        if "error" in data and not data.get("available", True):
            return data
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        services = []
        for item in (data.get("data", []) or [])[:20]:
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": (item.get("data", "") or "")[:200],
                "module": (item.get("_shodan", {}) or {}).get("module"),
            })
        return {
            "source": "shodan", "ip": ip,
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "os": data.get("os"),
            "ports": ports,
            "port_count": len(ports),
            "vulns": (vulns or [])[:20],
            "vuln_count": len(vulns or []),
            "services": services,
            "last_update": data.get("last_update"),
        }

    def resolve_domain(self, domain):
        data = self._request("GET", "/dns/resolve", params={"hostnames": domain, "key": self.api_key})
        if "error" in data and not data.get("available", True):
            return data
        return {"source": "shodan", "domain": domain, "ip": data.get(domain)}

    def reverse_ip(self, ip):
        data = self._request("GET", "/dns/reverse", params={"ips": ip, "key": self.api_key})
        if "error" in data and not data.get("available", True):
            return data
        return {"source": "shodan", "ip": ip, "hostnames": data.get(ip, [])}


# ============================================================
# GreyNoise (Community API)
# ============================================================

class GreyNoiseClient(BaseAPIClient):
    SERVICE_NAME = "GreyNoise"
    BASE_URL = "https://api.greynoise.io"
    REQUIRED_KEY = "GREYNOISE_API_KEY"

    def _default_headers(self):
        return {"key": self.api_key, "Accept": "application/json", "User-Agent": Config.USER_AGENT}

    def check_ip(self, ip):
        data = self._request("GET", "/v3/community/" + ip)
        if "error" in data and not data.get("available", True):
            return data
        return {
            "source": "greynoise", "ip": ip,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }


# ============================================================
# Have I Been Pwned (HIBP - k-anonymity)
# ============================================================

class HIBPClient(BaseAPIClient):
    SERVICE_NAME = "HIBP"
    BASE_URL = "https://api.pwnedpasswords.com"
    REQUIRED_KEY = ""

    @property
    def available(self):
        return True

    def check_password(self, password):
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        try:
            client = self._get_client()
            response = client.get("/range/" + prefix)
            if response.status_code != 200:
                return {"source": "hibp", "error": "HTTP " + str(response.status_code)}
            count = 0
            for line in response.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1])
                    break
            breached = count > 0
            if breached:
                msg = "Seen " + str(count) + " times in breaches"
            else:
                msg = "Not found in known breaches"
            return {
                "source": "hibp", "hash_prefix": prefix,
                "breached": breached, "breach_count": count,
                "message": msg,
            }
        except Exception as e:
            return {"source": "hibp", "error": str(e)}


# ============================================================
# NVD (National Vulnerability Database - public API)
# ============================================================

class NVDClient(BaseAPIClient):
    SERVICE_NAME = "NVD"
    BASE_URL = "https://services.nvd.nist.gov/rest/json"
    REQUIRED_KEY = ""

    @property
    def available(self):
        return True

    def lookup_cve(self, cve_id):
        data = self._request("GET", "/cves/2.0", params={"cveId": cve_id})
        if "error" in data and not data.get("available", True):
            return data
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"source": "nvd", "cve_id": cve_id, "found": False}
        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        en_desc = None
        for d in descriptions:
            if d.get("lang") == "en":
                en_desc = d["value"]
                break
        metrics = cve_data.get("metrics", {})
        cvss31_list = metrics.get("cvssMetricV31", [])
        cvss31 = cvss31_list[0] if cvss31_list else {}
        cvss_data = cvss31.get("cvssData", {}) if cvss31 else {}
        weakness_list = []
        for w in cve_data.get("weaknesses", []):
            w_descs = w.get("description", [])
            if w_descs:
                weakness_list.append(w_descs[0].get("value"))
        ref_list = []
        for r in cve_data.get("references", [])[:10]:
            ref_list.append(r.get("url"))
        return {
            "source": "nvd", "cve_id": cve_id, "found": True,
            "description": en_desc,
            "published": cve_data.get("published"),
            "modified": cve_data.get("lastModified"),
            "cvss_score": cvss_data.get("baseScore"),
            "cvss_severity": cvss_data.get("baseSeverity"),
            "cvss_vector": cvss_data.get("vectorString"),
            "exploitability_score": cvss31.get("exploitabilityScore"),
            "impact_score": cvss31.get("impactScore"),
            "weaknesses": weakness_list,
            "references": ref_list,
        }

    def search_cves(self, keyword, results_per_page=10):
        data = self._request("GET", "/cves/2.0", params={"keywordSearch": keyword, "resultsPerPage": results_per_page})
        if "error" in data and not data.get("available", True):
            return data
        vulns = data.get("vulnerabilities", [])
        results = []
        for v in vulns:
            cve = v.get("cve", {})
            descs = cve.get("descriptions", [])
            en_desc = None
            for d in descs:
                if d.get("lang") == "en":
                    en_desc = d["value"]
                    break
            results.append({
                "cve_id": cve.get("id"),
                "description": ((en_desc or "")[:300]),
                "published": cve.get("published"),
            })
        return {"source": "nvd", "query": keyword, "total_results": data.get("totalResults", 0), "results": results}


# ============================================================
# Client Registry (singleton access)
# ============================================================

_clients = {}


def get_client(name):
    if name not in _clients:
        client_map = {
            "virustotal": VirusTotalClient,
            "abuseipdb": AbuseIPDBClient,
            "shodan": ShodanClient,
            "greynoise": GreyNoiseClient,
            "hibp": HIBPClient,
            "nvd": NVDClient,
        }
        if name not in client_map:
            raise ValueError("Unknown API client: " + name)
        _clients[name] = client_map[name]()
    return _clients[name]


def get_available_apis():
    apis = {
        "virustotal": {"key": "VIRUSTOTAL_API_KEY", "description": "File, IP, domain, URL scanning"},
        "abuseipdb": {"key": "ABUSEIPDB_API_KEY", "description": "IP abuse reports and confidence scoring"},
        "shodan": {"key": "SHODAN_API_KEY", "description": "Port scanning, service detection, vulns"},
        "greynoise": {"key": "GREYNOISE_API_KEY", "description": "Internet noise and mass scanning detection"},
        "hibp": {"key": None, "description": "Password breach checking (no key needed)"},
        "nvd": {"key": None, "description": "CVE vulnerability database (no key needed)"},
    }
    result = {}
    for name in apis:
        info = apis[name]
        client = get_client(name)
        result[name] = {
            "available": client.available,
            "description": info["description"],
            "env_var": info["key"],
        }
    return result