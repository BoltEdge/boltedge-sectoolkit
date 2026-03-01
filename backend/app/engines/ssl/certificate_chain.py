"""
BoltEdge SecToolkit â€” Certificate Chain Engine
"""
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain
from app.config import Config


class CertificateChainEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.SSL_TIMEOUT

    def validate(self, domain: str, port: int = 443) -> dict:
        domain = validate_domain(domain)
        try:
            chain_der = self._fetch_chain(domain, port)
            chain = [self._parse_cert(x509.load_der_x509_certificate(c), i) for i, c in enumerate(chain_der)]
            chain_valid = all(c["valid"] for c in chain) and len(chain) > 0
            return {
                "domain": domain, "port": port, "chain_length": len(chain),
                "chain_valid": chain_valid, "chain": chain,
                "has_root": chain[-1]["is_self_signed"] if chain else False,
            }
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"Certificate chain validation failed: {str(e)}")

    def _fetch_chain(self, domain: str, port: int) -> list[bytes]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    chain = []
                    cert_binary = ssock.getpeercert(binary_form=True)
                    if cert_binary: chain.append(cert_binary)
                    return chain
        except socket.timeout: raise EngineTimeoutError(f"SSL connection timed out for {domain}:{port}")
        except ConnectionRefusedError: raise EngineError(f"Connection refused to {domain}:{port}")
        except Exception as e: raise EngineError(f"Failed to fetch certificate chain: {str(e)}")

    def _parse_cert(self, cert, index: int) -> dict:
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
        subject = self._name_to_str(cert.subject)
        issuer = self._name_to_str(cert.issuer)
        cert_type = "leaf" if index == 0 else ("root" if cert.subject == cert.issuer else "intermediate")
        return {
            "index": index, "type": cert_type, "subject": subject, "issuer": issuer,
            "is_self_signed": cert.subject == cert.issuer,
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_remaining": (not_after - now).days, "valid": not_before <= now <= not_after,
            "serial_number": format(cert.serial_number, "x"),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
            "signature_algorithm": str(cert.signature_hash_algorithm.name) if cert.signature_hash_algorithm else "unknown",
            "is_ca": self._is_ca(cert),
        }

    @staticmethod
    def _name_to_str(name):
        return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)

    @staticmethod
    def _is_ca(cert):
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            return bc.value.ca
        except x509.ExtensionNotFound: return False
