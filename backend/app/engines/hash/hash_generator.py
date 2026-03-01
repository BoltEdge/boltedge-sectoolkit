"""
BoltEdge SecToolkit â€” Hash Generator Engine
"""
import hashlib
from app.utils.exceptions import InvalidInputError


class HashGeneratorEngine:
    def generate(self, text: str, encoding: str = "utf-8") -> dict:
        if text is None: raise InvalidInputError("Empty input")
        data = text.encode(encoding)
        return {
            "input_length": len(text), "encoding": encoding,
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
                "sha224": hashlib.sha224(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
                "sha384": hashlib.sha384(data).hexdigest(), "sha512": hashlib.sha512(data).hexdigest(),
                "sha3_256": hashlib.sha3_256(data).hexdigest(), "sha3_512": hashlib.sha3_512(data).hexdigest(),
                "blake2b": hashlib.blake2b(data).hexdigest(), "blake2s": hashlib.blake2s(data).hexdigest(),
            },
        }
