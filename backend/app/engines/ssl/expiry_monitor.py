"""
BoltEdge SecToolkit â€” Expiry Monitor Engine
"""
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from app.utils.exceptions import EngineError, EngineTimeoutError
from app.utils.validators import validate_domain
from app.config import Config


class ExpiryMonitorEngine:
    def __init__(self, timeout: int = None):
        self.timeout = timeout or Config.SSL_TIMEOUT

    def check(self, domain: str, port: int = 443) -> dict:
        domain = validate_domain(domain)
        try:
            cert_der = self._fetch_cert(domain, port)
            cert = x509.load_der_x509_certificate(cert_der)
            now = datetime.now(timezone.utc)
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            days_remaining = (not_after - now).days
            total_validity = (not_after - not_before).days
            days_elapsed = (now - not_before).days
            percent_elapsed = round((days_elapsed / total_validity) * 100, 1) if total_validity > 0 else 0
            cn = None
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else None
            except Exception: pass
            issuer_cn = None
            try:
                issuer_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                issuer_cn = issuer_attrs[0].value if issuer_attrs else None
            except Exception: pass
            urgency = self._assess_urgency(days_remaining)
            return {
                "domain": domain, "port": port, "common_name": cn, "issuer": issuer_cn,
                "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
                "days_remaining": days_remaining, "total_validity_days": total_validity,
                "days_elapsed": days_elapsed, "percent_elapsed": percent_elapsed,
                "is_expired": days_remaining < 0, "is_valid": not_before <= now <= not_after,
                "urgency": urgency,
            }
        except (EngineError, EngineTimeoutError): raise
        except Exception as e: raise EngineError(f"Expiry check failed: {str(e)}")

    def _fetch_cert(self, domain, port) -> bytes:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert(binary_form=True)
        except socket.timeout: raise EngineTimeoutError(f"Connection timed out for {domain}:{port}")
        except ConnectionRefusedError: raise EngineError(f"Connection refused to {domain}:{port}")
        except Exception as e: raise EngineError(f"Failed to fetch certificate: {str(e)}")

    @staticmethod
    def _assess_urgency(days_remaining: int) -> dict:
        if days_remaining < 0: return {"level": "expired", "color": "red", "message": "Certificate has expired"}
        if days_remaining <= 7: return {"level": "critical", "color": "red", "message": "Expires within 7 days"}
        if days_remaining <= 14: return {"level": "high", "color": "orange", "message": "Expires within 14 days"}
        if days_remaining <= 30: return {"level": "warning", "color": "yellow", "message": "Expires within 30 days"}
        if days_remaining <= 60: return {"level": "notice", "color": "blue", "message": "Expires within 60 days"}
        return {"level": "ok", "color": "green", "message": "Certificate is valid"}
