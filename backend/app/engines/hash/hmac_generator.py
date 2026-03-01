"""
BoltEdge SecToolkit â€” HMAC Generator Engine
"""
import hashlib
import hmac
from app.utils.exceptions import InvalidInputError

_ALGORITHMS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha224": hashlib.sha224,
               "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512,
               "sha3_256": hashlib.sha3_256, "sha3_512": hashlib.sha3_512}

class HMACGeneratorEngine:
    def generate(self, message: str, key: str, algorithm: str = "sha256") -> dict:
        if not message: raise InvalidInputError("Message is required")
        if not key: raise InvalidInputError("Key is required")
        algo = algorithm.lower().replace("-", "_")
        if algo not in _ALGORITHMS:
            raise InvalidInputError(f"Unsupported algorithm: {algorithm}. Supported: {', '.join(_ALGORITHMS)}")
        digest = hmac.new(key.encode("utf-8"), message.encode("utf-8"), _ALGORITHMS[algo]).hexdigest()
        return {"message_length": len(message), "algorithm": algo, "hmac": digest, "hmac_length": len(digest)}
