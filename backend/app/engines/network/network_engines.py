"""
BoltEdge SecToolkit â€” Network Engines (8 tools)
"""
import socket
import ssl
import httpx
import re
from datetime import datetime, timezone
from app.engines.common.dns_resolver import DNSResolver
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_domain, validate_url, validate_mac
from app.config import Config


# 1. Status Checker
class StatusCheckerEngine:
    def __init__(self, timeout=None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def check(self, target):
        if not target.startswith(("http://", "https://")): target = f"https://{target}"
        try:
            import time; start = time.time()
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(target)
            elapsed = round((time.time() - start) * 1000, 1)
            return {"url": target, "is_up": 200 <= response.status_code < 400,
                    "status_code": response.status_code, "response_time_ms": elapsed,
                    "final_url": str(response.url), "server": response.headers.get("server"),
                    "content_type": response.headers.get("content-type"),
                    "checked_at": datetime.now(timezone.utc).isoformat()}
        except httpx.TimeoutException:
            return {"url": target, "is_up": False, "error": "Timed out", "checked_at": datetime.now(timezone.utc).isoformat()}
        except httpx.ConnectError:
            return {"url": target, "is_up": False, "error": "Connection refused", "checked_at": datetime.now(timezone.utc).isoformat()}
        except Exception as e:
            return {"url": target, "is_up": False, "error": str(e), "checked_at": datetime.now(timezone.utc).isoformat()}


# 2. DNS Leak Test
class DNSLeakTestEngine:
    def __init__(self, dns_resolver=None):
        self.dns = dns_resolver or DNSResolver()

    def test(self, domain="whoami.akamai.net"):
        resolvers = []
        for query, provider in [("whoami.akamai.net", "Akamai"), ("o-o.myaddr.l.google.com", "Google"), ("whoami.ultradns.net", "UltraDNS")]:
            try:
                results = self.dns.resolve(query, "TXT")
                if results: resolvers.append({"provider": provider, "query": query, "response": results})
            except (EngineError, EngineTimeoutError): continue
        return {"resolvers_detected": resolvers, "total_resolvers": len(resolvers),
                "potential_leak": len(resolvers) > 1, "checked_at": datetime.now(timezone.utc).isoformat()}


# 3. Whois History
class WhoisHistoryEngine:
    def __init__(self, db=None):
        self.db = db

    def lookup(self, domain):
        domain = validate_domain(domain)
        try:
            from app.models import WhoisHistory; from app import db as app_db
            db = self.db or app_db
            records = db.session.query(WhoisHistory).filter(WhoisHistory.domain == domain).order_by(WhoisHistory.checked_at.desc()).limit(50).all()
            entries = [{"checked_at": r.checked_at.isoformat() if r.checked_at else None,
                        "registrar": r.registrar, "nameservers": r.nameservers, "status": r.status} for r in records]
            return {"domain": domain, "total_records": len(entries), "history": entries}
        except Exception:
            return {"domain": domain, "total_records": 0, "history": [],
                    "message": "Whois history tracking will populate over time."}


# 4. MAC Lookup
_OUI_CACHE = {}

class MACLookupEngine:
    def lookup(self, mac):
        mac = validate_mac(mac)
        oui = mac.replace(":", "")[:6].upper()
        vendor = self._lookup_oui(oui)
        return {"mac": mac, "oui": oui, "vendor": vendor,
                "is_unicast": int(oui[1], 16) & 1 == 0,
                "is_local": int(oui[1], 16) & 2 != 0, "normalized": mac}

    def _lookup_oui(self, oui):
        if _OUI_CACHE: return _OUI_CACHE.get(oui)
        try:
            oui_path = Config.OUI_DB
            if oui_path.exists():
                with open(oui_path, "r") as f:
                    for line in f:
                        if "(hex)" in line:
                            parts = line.split("(hex)")
                            _OUI_CACHE[parts[0].strip().replace("-", "").upper()] = parts[1].strip()
                return _OUI_CACHE.get(oui)
        except Exception: pass
        return None


# 5. HTTP/2 Check
class HTTP2CheckEngine:
    def __init__(self, timeout=None):
        self.timeout = timeout or Config.SSL_TIMEOUT

    def check(self, domain, port=443):
        domain = validate_domain(domain)
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    negotiated = ssock.selected_alpn_protocol()
                    return {"domain": domain, "port": port, "supports_http2": negotiated == "h2",
                            "negotiated_protocol": negotiated, "alpn_offered": ["h2", "http/1.1"]}
        except socket.timeout: raise EngineTimeoutError(f"Connection timed out for {domain}:{port}")
        except Exception as e: raise EngineError(f"HTTP/2 check failed: {str(e)}")


# 6. HSTS Check
class HSTSCheckEngine:
    def __init__(self, timeout=None):
        self.timeout = timeout or Config.HTTP_TIMEOUT

    def check(self, domain):
        domain = validate_domain(domain)
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(f"https://{domain}")
            hsts = response.headers.get("strict-transport-security")
            if not hsts:
                return {"domain": domain, "has_hsts": False, "header": None, "issues": ["No HSTS header found"]}
            parsed = self._parse_hsts(hsts); issues = self._validate(parsed)
            return {"domain": domain, "has_hsts": True, "header": hsts,
                    "max_age": parsed.get("max_age"),
                    "max_age_days": parsed["max_age"] // 86400 if parsed.get("max_age") else None,
                    "include_subdomains": parsed.get("includeSubDomains", False),
                    "preload": parsed.get("preload", False), "issues": issues}
        except Exception as e: raise EngineError(f"HSTS check failed: {str(e)}")

    @staticmethod
    def _parse_hsts(header):
        parsed = {}
        for part in header.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                try: parsed["max_age"] = int(part.split("=", 1)[1])
                except ValueError: pass
            elif part == "includesubdomains": parsed["includeSubDomains"] = True
            elif part == "preload": parsed["preload"] = True
        return parsed

    @staticmethod
    def _validate(parsed):
        issues = []
        if parsed.get("max_age", 0) < 31536000: issues.append(f"max-age is {parsed.get('max_age', 0)}s â€” recommended minimum is 31536000 (1 year)")
        if not parsed.get("includeSubDomains"): issues.append("Missing includeSubDomains directive")
        if not parsed.get("preload"): issues.append("Missing preload directive â€” required for HSTS preload list")
        return issues


# 7. MTU Calculator
class MTUCalculatorEngine:
    def calculate(self, protocol="ethernet", overhead=0):
        defaults = {"ethernet": {"mtu": 1500, "header": 14, "desc": "Standard Ethernet"},
                    "pppoe": {"mtu": 1492, "header": 8, "desc": "PPPoE (DSL)"},
                    "vpn_ipsec": {"mtu": 1400, "header": 50, "desc": "IPSec VPN"},
                    "vpn_wireguard": {"mtu": 1420, "header": 60, "desc": "WireGuard VPN"},
                    "vpn_openvpn": {"mtu": 1400, "header": 48, "desc": "OpenVPN"},
                    "gre": {"mtu": 1476, "header": 24, "desc": "GRE Tunnel"},
                    "vxlan": {"mtu": 1450, "header": 50, "desc": "VXLAN Overlay"},
                    "jumbo": {"mtu": 9000, "header": 14, "desc": "Jumbo Frames"}}
        proto = protocol.lower().replace(" ", "_").replace("-", "_")
        config = defaults.get(proto, defaults["ethernet"])
        effective = config["mtu"] - overhead
        return {"protocol": proto, "description": config["desc"], "mtu": config["mtu"],
                "header_overhead": config["header"], "custom_overhead": overhead,
                "effective_mtu": effective, "max_payload": effective - 28, "tcp_mss": effective - 40,
                "all_protocols": {k: v["mtu"] for k, v in defaults.items()}}


# 8. Bandwidth Calculator
class BandwidthCalculatorEngine:
    def calculate(self, file_size_mb=None, bandwidth_mbps=None, time_seconds=None):
        if file_size_mb and bandwidth_mbps:
            t = (file_size_mb * 8) / bandwidth_mbps
            return {"mode": "calculate_time", "file_size_mb": file_size_mb,
                    "bandwidth_mbps": bandwidth_mbps, "transfer_time_seconds": round(t, 2),
                    "transfer_time_minutes": round(t / 60, 2), "transfer_time_human": self._human(t)}
        elif file_size_mb and time_seconds:
            bw = (file_size_mb * 8) / time_seconds
            return {"mode": "calculate_bandwidth", "file_size_mb": file_size_mb,
                    "time_seconds": time_seconds, "required_bandwidth_mbps": round(bw, 2)}
        elif bandwidth_mbps and time_seconds:
            size = (bandwidth_mbps * time_seconds) / 8
            return {"mode": "calculate_size", "bandwidth_mbps": bandwidth_mbps,
                    "time_seconds": time_seconds, "max_file_size_mb": round(size, 2)}
        else: raise InvalidInputError("Provide at least 2 of: file_size_mb, bandwidth_mbps, time_seconds")

    @staticmethod
    def _human(s):
        if s < 1: return f"{round(s*1000)}ms"
        if s < 60: return f"{round(s,1)}s"
        if s < 3600: return f"{int(s//60)}m {int(s%60)}s"
        return f"{int(s//3600)}h {int((s%3600)//60)}m"
