"""
BoltEdge SecToolkit â€” Subdomain Finder Engine

Tool: Domain -> Subdomain Finder
Description: Discover subdomains for a domain.
Input: Domain name
Output: Found subdomains with IP addresses and status
"""
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain


_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay",
    "api", "app", "dev", "staging", "test", "qa", "uat",
    "admin", "portal", "dashboard", "panel", "console",
    "blog", "shop", "store", "cms", "cdn", "static", "assets", "media",
    "vpn", "remote", "gateway", "proxy",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "git", "gitlab", "github", "svn", "repo",
    "ci", "jenkins", "build", "deploy",
    "monitor", "grafana", "kibana", "elastic", "prometheus",
    "login", "auth", "sso", "oauth", "id", "accounts",
    "docs", "wiki", "help", "support", "status", "health",
    "beta", "alpha", "preview", "demo", "sandbox",
    "m", "mobile", "wap",
    "cloud", "aws", "azure", "gcp",
    "intranet", "internal", "corp", "office",
    "backup", "bak", "old", "new", "v2", "v3",
    "autodiscover", "autoconfig", "cpanel", "whm", "plesk",
    "webdisk", "cpcalendars", "cpcontacts",
    "secure", "ssl", "tls",
    "img", "images", "video", "files", "download", "upload",
    "search", "analytics", "track", "tracking",
    "news", "forum", "community",
]


class SubdomainFinderEngine:
    """Discover subdomains via DNS brute-force."""

    def __init__(self, dns_resolver: DNSResolver = None):
        self.dns = dns_resolver or DNSResolver()

    def find(self, domain: str, wordlist: list[str] = None) -> dict:
        domain = validate_domain(domain)
        wordlist = wordlist or _COMMON_SUBDOMAINS

        try:
            found = []
            checked = 0

            for prefix in wordlist:
                subdomain = f"{prefix}.{domain}"
                checked += 1

                try:
                    a_records = self.dns.resolve(subdomain, "A")
                    if a_records:
                        aaaa_records = self.dns.resolve(subdomain, "AAAA")
                        cname_records = self.dns.resolve(subdomain, "CNAME")

                        found.append({
                            "subdomain": subdomain,
                            "a_records": a_records,
                            "aaaa_records": aaaa_records,
                            "cname_records": cname_records,
                            "method": "dns_bruteforce",
                        })

                except (EngineError, EngineTimeoutError):
                    continue

            return {
                "domain": domain,
                "total_found": len(found),
                "total_checked": checked,
                "subdomains": found,
                "method": "dns_bruteforce",
                "wordlist_size": len(wordlist),
            }

        except Exception as e:
            raise EngineError(f"Subdomain discovery failed: {str(e)}")
