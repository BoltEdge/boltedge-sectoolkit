"""
SecToolkit 101 â€” Hash Identifier Engine
"""
import re
from app.utils.exceptions import InvalidInputError

_HASH_PATTERNS = [
    {"name": "MD5", "length": 32, "regex": r"^[a-fA-F0-9]{32}$"},
    {"name": "SHA-1", "length": 40, "regex": r"^[a-fA-F0-9]{40}$"},
    {"name": "SHA-224", "length": 56, "regex": r"^[a-fA-F0-9]{56}$"},
    {"name": "SHA-256", "length": 64, "regex": r"^[a-fA-F0-9]{64}$"},
    {"name": "SHA-384", "length": 96, "regex": r"^[a-fA-F0-9]{96}$"},
    {"name": "SHA-512", "length": 128, "regex": r"^[a-fA-F0-9]{128}$"},
    {"name": "SHA3-256", "length": 64, "regex": r"^[a-fA-F0-9]{64}$"},
    {"name": "SHA3-512", "length": 128, "regex": r"^[a-fA-F0-9]{128}$"},
    {"name": "BLAKE2b-256", "length": 64, "regex": r"^[a-fA-F0-9]{64}$"},
    {"name": "BLAKE2b-512", "length": 128, "regex": r"^[a-fA-F0-9]{128}$"},
    {"name": "RIPEMD-160", "length": 40, "regex": r"^[a-fA-F0-9]{40}$"},
    {"name": "CRC32", "length": 8, "regex": r"^[a-fA-F0-9]{8}$"},
    {"name": "NTLM", "length": 32, "regex": r"^[a-fA-F0-9]{32}$"},
    {"name": "MySQL 5.x", "length": 40, "regex": r"^\*[a-fA-F0-9]{40}$"},
    {"name": "bcrypt", "length": None, "regex": r"^\$2[aby]?\$\d{2}\$.{53}$"},
    {"name": "Argon2", "length": None, "regex": r"^\$argon2(i|d|id)\$"},
    {"name": "MD5 Unix", "length": None, "regex": r"^\$1\$.{8}\$.{22}$"},
    {"name": "SHA-256 Unix", "length": None, "regex": r"^\$5\$"},
    {"name": "SHA-512 Unix", "length": None, "regex": r"^\$6\$"},
]

class HashIdentifierEngine:
    def identify(self, hash_string: str) -> dict:
        if not hash_string or not hash_string.strip(): raise InvalidInputError("Empty hash input")
        hash_string = hash_string.strip()
        length = len(hash_string)
        matches = []
        for pattern in _HASH_PATTERNS:
            if re.match(pattern["regex"], hash_string):
                confidence = "high" if pattern.get("length") and len([p for p in _HASH_PATTERNS if p.get("length") == length]) == 1 else "medium"
                matches.append({"type": pattern["name"], "confidence": confidence})
        is_hex = bool(re.match(r"^[a-fA-F0-9]+$", hash_string))
        return {"hash": hash_string, "length": length, "is_hex": is_hex,
                "possible_types": matches, "best_match": matches[0]["type"] if matches else None,
                "identified": len(matches) > 0}
