"""
BoltEdge SecToolkit â€” TLS Version Check Engine
"""
import ssl
import socket
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain
from app.config import Config


_TLS_VERSIONS = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, 'TLSv1_2') else None),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
    ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None),
]


class TLSVersionCheckEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.SSL_TIMEOUT

    def check(self, domain: str, port: int = 443) -> dict:
        domain = validate_domain(domain)
        try:
            results = [self._test_version(domain, port, name, version) for name, version in _TLS_VERSIONS]
            supported = [r["version"] for r in results if r["supported"]]
            deprecated = [v for v in supported if v in ("TLSv1.0", "TLSv1.1")]
            return {
                "domain": domain, "port": port,
                "best_version": supported[0] if supported else None,
                "supported_versions": supported, "deprecated_versions": deprecated,
                "has_deprecated": len(deprecated) > 0, "has_tls13": "TLSv1.3" in supported,
                "results": results,
            }
        except Exception as e: raise EngineError(f"TLS version check failed: {str(e)}")

    def _test_version(self, domain, port, name, version) -> dict:
        if version is None:
            return {"version": name, "supported": False, "cipher": None, "error": "Not available in this Python build"}
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    return {"version": name, "supported": True, "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None, "negotiated_protocol": ssock.version(), "error": None}
        except ssl.SSLError as e:
            return {"version": name, "supported": False, "cipher": None, "error": str(e)}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return {"version": name, "supported": False, "cipher": None, "error": "Connection failed"}
