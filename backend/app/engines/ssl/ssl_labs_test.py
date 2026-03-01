"""
BoltEdge SecToolkit â€” SSL Labs Test Engine (local grading)
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


class SSLLabsTestEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.SSL_TIMEOUT

    def grade(self, domain: str, port: int = 443) -> dict:
        domain = validate_domain(domain)
        try:
            protocols = self._test_protocols(domain, port)
            cipher_info = self._get_cipher_info(domain, port)
            vulns = self._check_vulnerabilities(protocols, cipher_info)
            grade = self._calculate_grade(protocols, cipher_info, vulns)
            return {
                "domain": domain, "port": port,
                "grade": grade["letter"], "grade_score": grade["score"],
                "protocols": protocols, "cipher": cipher_info,
                "vulnerabilities": vulns, "recommendations": grade["recommendations"],
            }
        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"SSL grading failed: {str(e)}")

    def _test_protocols(self, domain: str, port: int) -> list[dict]:
        results = []
        for name, version in _TLS_VERSIONS:
            if version is None:
                results.append({"version": name, "supported": False, "error": "Not available in this Python build"})
                continue
            supported = self._test_single_protocol(domain, port, version)
            results.append({"version": name, "supported": supported})
        return results

    def _test_single_protocol(self, domain: str, port: int, version) -> bool:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return True
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _get_cipher_info(self, domain: str, port: int) -> dict:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    return {"name": cipher[0] if cipher else None, "protocol": cipher[1] if cipher else None, "bits": cipher[2] if cipher else None}
        except Exception:
            return {"name": None, "protocol": None, "bits": None}

    @staticmethod
    def _check_vulnerabilities(protocols: list[dict], cipher_info: dict) -> dict:
        supported = {p["version"] for p in protocols if p["supported"]}
        vulns = {
            "tls10_enabled": "TLSv1.0" in supported,
            "tls11_enabled": "TLSv1.1" in supported,
            "no_tls13": "TLSv1.3" not in supported,
            "weak_cipher": cipher_info.get("bits", 256) < 128 if cipher_info.get("bits") else False,
        }
        vulns["has_vulnerabilities"] = any([vulns["tls10_enabled"], vulns["tls11_enabled"], vulns["weak_cipher"]])
        return vulns

    @staticmethod
    def _calculate_grade(protocols, cipher_info, vulns) -> dict:
        score = 100
        recommendations = []
        supported = {p["version"] for p in protocols if p["supported"]}
        if "TLSv1.0" in supported:
            score -= 30; recommendations.append("Disable TLS 1.0")
        if "TLSv1.1" in supported:
            score -= 20; recommendations.append("Disable TLS 1.1")
        if "TLSv1.3" not in supported:
            score -= 10; recommendations.append("Enable TLS 1.3")
        if "TLSv1.2" not in supported and "TLSv1.3" not in supported:
            score -= 40; recommendations.append("CRITICAL: No modern TLS versions supported")
        bits = cipher_info.get("bits", 0)
        if bits and bits < 128:
            score -= 30; recommendations.append("Weak cipher strength")
        elif bits and bits < 256:
            score -= 5
        if score >= 95: letter = "A+"
        elif score >= 85: letter = "A"
        elif score >= 75: letter = "B"
        elif score >= 60: letter = "C"
        elif score >= 40: letter = "D"
        else: letter = "F"
        if not recommendations: recommendations.append("SSL/TLS configuration looks good")
        return {"letter": letter, "score": max(score, 0), "recommendations": recommendations}
