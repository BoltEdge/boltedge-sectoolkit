"""
SecToolkit 101 â€” SHA Generator Engine
"""
import hashlib
from app.utils.exceptions import InvalidInputError

_SHA_VARIANTS = {
    "sha1": hashlib.sha1, "sha224": hashlib.sha224, "sha256": hashlib.sha256,
    "sha384": hashlib.sha384, "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224, "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384, "sha3_512": hashlib.sha3_512,
}

class SHAGeneratorEngine:
    def generate(self, text: str, variant: str = None) -> dict:
        if text is None: raise InvalidInputError("Empty input")
        data = text.encode("utf-8")
        if variant:
            v = variant.lower().replace("-", "_")
            if v not in _SHA_VARIANTS:
                raise InvalidInputError(f"Unknown SHA variant: {variant}. Supported: {', '.join(_SHA_VARIANTS)}")
            return {"input_length": len(text), "algorithm": variant, "hash": _SHA_VARIANTS[v](data).hexdigest()}
        return {"input_length": len(text), "hashes": {name: func(data).hexdigest() for name, func in _SHA_VARIANTS.items()}}
