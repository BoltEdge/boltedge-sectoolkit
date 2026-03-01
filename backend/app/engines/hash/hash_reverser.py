"""
BoltEdge SecToolkit â€” Hash Reverser Engine
"""
import hashlib
from app.utils.exceptions import InvalidInputError
from app.utils.validators import validate_hash, identify_hash_type

_COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football", "password1",
    "password123", "batman", "login", "admin", "welcome", "hello",
    "charlie", "donald", "lovely", "jesus", "password2", "test",
    "test123", "root", "toor", "changeme", "guest", "default",
    "secret", "pass", "pass123", "pass1234", "1234", "12345",
    "123456789", "1234567890", "0987654321", "111111", "000000",
]

class HashReverserEngine:
    def reverse(self, hash_string: str) -> dict:
        if not hash_string or not hash_string.strip(): raise InvalidInputError("Empty hash input")
        hash_string = hash_string.strip().lower()
        hash_type = identify_hash_type(hash_string)
        hash_funcs = self._get_hash_funcs(len(hash_string))
        if not hash_funcs:
            return {"hash": hash_string, "hash_type": hash_type, "found": False, "plaintext": None,
                    "method": "wordlist", "message": "Unsupported hash length for reversal"}
        for password in _COMMON_PASSWORDS:
            for algo_name, algo_func in hash_funcs:
                if algo_func(password.encode("utf-8")).hexdigest() == hash_string:
                    return {"hash": hash_string, "hash_type": algo_name, "found": True,
                            "plaintext": password, "method": "wordlist",
                            "warning": "This password is extremely common and insecure."}
        return {"hash": hash_string, "hash_type": hash_type, "found": False, "plaintext": None,
                "method": "wordlist", "checked": len(_COMMON_PASSWORDS),
                "message": "Hash not found in common password list."}

    @staticmethod
    def _get_hash_funcs(length):
        return {32: [("MD5", hashlib.md5)], 40: [("SHA-1", hashlib.sha1)],
                64: [("SHA-256", hashlib.sha256)], 128: [("SHA-512", hashlib.sha512)]}.get(length, [])
