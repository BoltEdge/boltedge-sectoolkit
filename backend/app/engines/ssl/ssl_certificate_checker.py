"""
BoltEdge SecToolkit â€” SSL Certificate Checker Engine
"""
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain
from app.config import Config


class SSLCertificateCheckerEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.SSL_TIMEOUT

    def check(self, domain: str, port: int = 443) -> dict:
        domain = validate_domain(domain)
        try:
            cert_pem, cert_binary = self._fetch_certificate(domain, port)
            cert = x509.load_der_x509_certificate(cert_binary)

            now = datetime.now(timezone.utc)
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)

            days_remaining = (not_after - now).days
            is_valid = not_before <= now <= not_after
            sans = self._extract_sans(cert)
            subject = self._extract_name(cert.subject)
            issuer = self._extract_name(cert.issuer)

            return {
                "domain": domain, "port": port, "valid": is_valid,
                "subject": subject, "issuer": issuer,
                "validity": {
                    "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
                    "days_remaining": days_remaining, "is_expired": days_remaining < 0,
                    "expiring_soon": 0 < days_remaining <= 30,
                },
                "sans": sans, "san_count": len(sans),
                "serial_number": format(cert.serial_number, "x"),
                "version": cert.version.value,
                "signature_algorithm": cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"),
                "fingerprints": {
                    "sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
                    "sha1": cert.fingerprint(hashes.SHA1()).hex(":"),
                },
                "key_info": self._extract_key_info(cert),
                "is_self_signed": subject == issuer,
                "is_wildcard": any(s.startswith("*.") for s in sans),
            }
        except (EngineError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"SSL certificate check failed: {str(e)}")

    def _fetch_certificate(self, domain: str, port: int) -> tuple:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_binary)
                    return cert_pem, cert_binary
        except socket.timeout:
            raise EngineTimeoutError(f"SSL connection timed out for {domain}:{port}")
        except ConnectionRefusedError:
            raise EngineError(f"Connection refused to {domain}:{port}")
        except socket.gaierror:
            raise EngineError(f"Could not resolve {domain}")
        except Exception as e:
            raise EngineError(f"Failed to fetch certificate: {str(e)}")

    @staticmethod
    def _extract_sans(cert: x509.Certificate) -> list[str]:
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_name(name: x509.Name) -> dict:
        fields = {}
        oid_map = {
            x509.oid.NameOID.COMMON_NAME: "common_name",
            x509.oid.NameOID.ORGANIZATION_NAME: "organisation",
            x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME: "organisational_unit",
            x509.oid.NameOID.COUNTRY_NAME: "country",
            x509.oid.NameOID.STATE_OR_PROVINCE_NAME: "state",
            x509.oid.NameOID.LOCALITY_NAME: "locality",
        }
        for oid, key in oid_map.items():
            try:
                values = name.get_attributes_for_oid(oid)
                if values:
                    fields[key] = values[0].value
            except Exception:
                pass
        return fields

    @staticmethod
    def _extract_key_info(cert: x509.Certificate) -> dict:
        pub_key = cert.public_key()
        info = {"type": type(pub_key).__name__}
        try:
            info["size"] = pub_key.key_size
        except AttributeError:
            pass
        return info
