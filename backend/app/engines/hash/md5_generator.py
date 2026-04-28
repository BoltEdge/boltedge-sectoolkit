"""
SecToolkit 101 â€” MD5 Generator Engine
"""
import hashlib
from app.utils.exceptions import InvalidInputError


class MD5GeneratorEngine:
    def generate(self, text: str) -> dict:
        if text is None: raise InvalidInputError("Empty input")
        data = text.encode("utf-8")
        return {"input_length": len(text), "algorithm": "MD5", "hash": hashlib.md5(data).hexdigest(),
                "warning": "MD5 is cryptographically broken â€” do not use for security purposes. Use SHA-256 or better."}
