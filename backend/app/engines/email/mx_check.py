"""
BoltEdge SecToolkit â€” MX Check Engine
"""
import smtplib
import socket
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain
from app.config import Config


class MXCheckEngine:
    def __init__(self, dns_resolver: DNSResolver = None, timeout: int = None):
        self.dns = dns_resolver or DNSResolver()
        self.timeout = timeout or Config.SMTP_TIMEOUT

    def check(self, domain: str) -> dict:
        domain = validate_domain(domain)
        try:
            mx_records = self.dns.resolve(domain, "MX")
            if not mx_records:
                return {"domain": domain, "has_mx": False, "servers": [], "issues": ["No MX records found"]}
            servers = []
            for record in mx_records:
                parts = record.split()
                priority = int(parts[0]) if len(parts) >= 2 else 0
                hostname = parts[-1].rstrip(".")
                server_check = self._check_server(hostname)
                server_check["priority"] = priority; server_check["hostname"] = hostname
                servers.append(server_check)
            servers.sort(key=lambda s: s["priority"])
            issues = []
            if not any(s["reachable"] for s in servers): issues.append("No MX servers are reachable on port 25")
            if not any(s.get("supports_tls") for s in servers): issues.append("No MX servers support STARTTLS")
            return {"domain": domain, "has_mx": True, "total_servers": len(servers),
                    "reachable_count": sum(1 for s in servers if s["reachable"]),
                    "tls_count": sum(1 for s in servers if s.get("supports_tls")),
                    "servers": servers, "issues": issues}
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"MX check failed: {str(e)}")

    def _check_server(self, hostname):
        result = {"reachable": False, "banner": None, "supports_tls": False, "tls_version": None, "error": None}
        try:
            with smtplib.SMTP(hostname, 25, timeout=self.timeout) as smtp:
                result["reachable"] = True
                code, msg = smtp.ehlo()
                ehlo_response = msg.decode(errors="replace")
                result["banner"] = ehlo_response.split("\n")[0] if ehlo_response else None
                if "STARTTLS" in ehlo_response.upper():
                    try:
                        smtp.starttls(); result["supports_tls"] = True
                        cipher = smtp.sock.cipher() if hasattr(smtp.sock, 'cipher') else None
                        if cipher: result["tls_version"] = cipher[1]
                    except Exception: result["supports_tls"] = False
                smtp.quit()
        except smtplib.SMTPConnectError as e: result["error"] = f"Connection refused: {str(e)}"
        except socket.timeout: result["error"] = "Connection timed out"
        except socket.gaierror: result["error"] = "Could not resolve hostname"
        except Exception as e: result["error"] = str(e)
        return result
