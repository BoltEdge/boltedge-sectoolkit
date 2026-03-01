"""
BoltEdge SecToolkit â€” Certificate Decoder Engine
"""
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from app.utils.exceptions import EngineError, InvalidInputError


class CertificateDecoderEngine:
    def decode(self, pem_data: str) -> dict:
        pem_data = self._normalize_pem(pem_data)
        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode())
        except Exception as e:
            raise InvalidInputError(f"Could not parse certificate: {str(e)}")
        try:
            now = datetime.now(timezone.utc)
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            return {
                "subject": self._name_to_dict(cert.subject), "issuer": self._name_to_dict(cert.issuer),
                "validity": {"not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
                             "days_remaining": (not_after - now).days, "is_valid": not_before <= now <= not_after},
                "serial_number": format(cert.serial_number, "x"), "version": f"v{cert.version.value + 1}",
                "signature_algorithm": str(cert.signature_hash_algorithm.name) if cert.signature_hash_algorithm else "unknown",
                "fingerprints": {"sha256": cert.fingerprint(hashes.SHA256()).hex(":"), "sha1": cert.fingerprint(hashes.SHA1()).hex(":"), "md5": cert.fingerprint(hashes.MD5()).hex(":")},
                "public_key": self._extract_key_info(cert), "extensions": self._extract_extensions(cert),
                "is_self_signed": cert.subject == cert.issuer, "is_ca": self._is_ca(cert), "pem": pem_data,
            }
        except InvalidInputError: raise
        except Exception as e: raise EngineError(f"Certificate decode failed: {str(e)}")

    @staticmethod
    def _normalize_pem(pem_data: str) -> str:
        pem_data = pem_data.strip()
        if not pem_data.startswith("-----BEGIN"):
            pem_data = f"-----BEGIN CERTIFICATE-----\n{pem_data}\n-----END CERTIFICATE-----"
        return pem_data

    @staticmethod
    def _name_to_dict(name: x509.Name) -> dict:
        fields = {}
        oid_map = {x509.oid.NameOID.COMMON_NAME: "CN", x509.oid.NameOID.ORGANIZATION_NAME: "O",
                   x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU", x509.oid.NameOID.COUNTRY_NAME: "C",
                   x509.oid.NameOID.STATE_OR_PROVINCE_NAME: "ST", x509.oid.NameOID.LOCALITY_NAME: "L",
                   x509.oid.NameOID.EMAIL_ADDRESS: "E"}
        for oid, key in oid_map.items():
            attrs = name.get_attributes_for_oid(oid)
            if attrs: fields[key] = attrs[0].value
        return fields

    @staticmethod
    def _extract_key_info(cert):
        pub_key = cert.public_key()
        info = {"type": type(pub_key).__name__}
        try: info["size"] = pub_key.key_size
        except AttributeError: pass
        return info

    @staticmethod
    def _extract_extensions(cert):
        extensions = []
        for ext in cert.extensions:
            entry = {"oid": ext.oid.dotted_string, "name": ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid), "critical": ext.critical}
            if isinstance(ext.value, x509.SubjectAlternativeName):
                entry["dns_names"] = ext.value.get_values_for_type(x509.DNSName)
                try: entry["ip_addresses"] = [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
                except Exception: entry["ip_addresses"] = []
            elif isinstance(ext.value, x509.BasicConstraints):
                entry["ca"] = ext.value.ca; entry["path_length"] = ext.value.path_length
            elif isinstance(ext.value, x509.KeyUsage):
                entry["usages"] = []
                for usage in ["digital_signature", "key_encipherment", "key_agreement", "content_commitment", "data_encipherment", "key_cert_sign", "crl_sign"]:
                    try:
                        if getattr(ext.value, usage): entry["usages"].append(usage)
                    except Exception: pass
            extensions.append(entry)
        return extensions

    @staticmethod
    def _is_ca(cert):
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            return bc.value.ca
        except x509.ExtensionNotFound: return False
