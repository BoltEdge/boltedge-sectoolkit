"""
BoltEdge SecToolkit â€” bcrypt Generator Engine
"""
import bcrypt
from app.utils.exceptions import InvalidInputError, EngineError


class BcryptGeneratorEngine:
    def generate(self, password: str, rounds: int = 12) -> dict:
        if not password: raise InvalidInputError("Password is required")
        rounds = max(4, min(rounds, 16))
        try:
            salt = bcrypt.gensalt(rounds=rounds)
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
            return {"password_length": len(password), "algorithm": "bcrypt",
                    "rounds": rounds, "hash": hashed.decode("utf-8")}
        except Exception as e: raise EngineError(f"bcrypt generation failed: {str(e)}")

    def verify(self, password: str, hash_string: str) -> dict:
        if not password or not hash_string: raise InvalidInputError("Password and hash are required")
        try:
            match = bcrypt.checkpw(password.encode("utf-8"), hash_string.encode("utf-8"))
            return {"match": match, "algorithm": "bcrypt"}
        except Exception as e: raise EngineError(f"bcrypt verification failed: {str(e)}")
