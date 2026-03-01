"""
BoltEdge SecToolkit â€” Argon2 Generator Engine
"""
from app.utils.exceptions import InvalidInputError, EngineError


class Argon2GeneratorEngine:
    def generate(self, password: str, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4) -> dict:
        if not password: raise InvalidInputError("Password is required")
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
            hashed = ph.hash(password)
            return {"password_length": len(password), "algorithm": "argon2id",
                    "parameters": {"time_cost": time_cost, "memory_cost": memory_cost, "parallelism": parallelism},
                    "hash": hashed}
        except ImportError:
            import hashlib, os, base64
            salt = os.urandom(16)
            derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
            return {"password_length": len(password), "algorithm": "pbkdf2_sha256 (argon2 not installed)",
                    "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(derived).decode()}
        except Exception as e: raise EngineError(f"Argon2 generation failed: {str(e)}")

    def verify(self, password: str, hash_string: str) -> dict:
        if not password or not hash_string: raise InvalidInputError("Password and hash are required")
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            ph = PasswordHasher()
            try: ph.verify(hash_string, password); return {"match": True, "algorithm": "argon2"}
            except VerifyMismatchError: return {"match": False, "algorithm": "argon2"}
        except ImportError: raise EngineError("argon2-cffi library not installed")
