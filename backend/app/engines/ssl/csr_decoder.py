"""
BoltEdge SecToolkit â€” CSR Decoder Engine
"""
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from app.utils.exceptions import EngineError, InvalidInputError


class CSRDecoderEngine:
    def decode(self, pem_data: str) -> dict:
        pem_data = self._normalize_pem(pem_data)
        try:
            csr = x509.load_pem_x509_csr(pem_data.encode())
        except Exception as e:
            raise InvalidInputError(f"Could not parse CSR: {str(e)}")
        try:
            subject = self._name_to_dict(csr.subject)
            sans = []
            try:
                san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound: pass
            pub_key = csr.public_key()
            key_info = {"type": type(pub_key).__name__}
            try: key_info["size"] = pub_key.key_size
            except AttributeError: pass
            return {
                "subject": subject, "sans": sans, "san_count": len(sans),
                "public_key": key_info, "signature_valid": csr.is_signature_valid,
                "signature_algorithm": str(csr.signature_hash_algorithm.name) if csr.signature_hash_algorithm else "unknown",
                "extensions": self._extract_extensions(csr), "pem": pem_data,
            }
        except InvalidInputError: raise
        except Exception as e: raise EngineError(f"CSR decode failed: {str(e)}")

    @staticmethod
    def _normalize_pem(pem_data: str) -> str:
        pem_data = pem_data.strip()
        if not pem_data.startswith("-----BEGIN"):
            pem_data = f"-----BEGIN CERTIFICATE REQUEST-----\n{pem_data}\n-----END CERTIFICATE REQUEST-----"
        return pem_data

    @staticmethod
    def _name_to_dict(name):
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
    def _extract_extensions(csr):
        return [{"oid": ext.oid.dotted_string, "name": ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid), "critical": ext.critical} for ext in csr.extensions]
