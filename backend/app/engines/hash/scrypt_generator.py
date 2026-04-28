"""
SecToolkit 101 â€” scrypt Generator Engine
"""
import hashlib
import os
import base64
from app.utils.exceptions import InvalidInputError, EngineError


class ScryptGeneratorEngine:
    def generate(self, password: str, n: int = 16384, r: int = 8, p: int = 1, dk_len: int = 32) -> dict:
        if not password: raise InvalidInputError("Password is required")
        try:
            salt = os.urandom(16)
            derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dk_len)
            return {"password_length": len(password), "algorithm": "scrypt",
                    "parameters": {"n": n, "r": r, "p": p, "dk_len": dk_len},
                    "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(derived).decode(),
                    "hash_hex": derived.hex()}
        except Exception as e: raise EngineError(f"scrypt generation failed: {str(e)}")
