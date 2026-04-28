"""
SecToolkit 101 â€” PBKDF2 Generator Engine
"""
import hashlib
import os
import base64
from app.utils.exceptions import InvalidInputError


class PBKDF2GeneratorEngine:
    def generate(self, password: str, iterations: int = 100000, algorithm: str = "sha256", dk_len: int = 32) -> dict:
        if not password: raise InvalidInputError("Password is required")
        algo = algorithm.lower()
        if algo not in ("sha1", "sha256", "sha384", "sha512"):
            raise InvalidInputError(f"Unsupported algorithm: {algorithm}")
        iterations = max(1000, min(iterations, 1000000))
        salt = os.urandom(16)
        derived = hashlib.pbkdf2_hmac(algo, password.encode("utf-8"), salt, iterations, dklen=dk_len)
        return {"password_length": len(password), "algorithm": f"pbkdf2_{algo}", "iterations": iterations,
                "dk_len": dk_len, "salt": base64.b64encode(salt).decode(),
                "hash": base64.b64encode(derived).decode(), "hash_hex": derived.hex()}
