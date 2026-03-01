"""
BoltEdge SecToolkit â€” Hash Comparer Engine
"""
import hashlib
from app.utils.exceptions import InvalidInputError


class HashComparerEngine:
    def compare(self, hash1: str, hash2: str) -> dict:
        if not hash1 or not hash2: raise InvalidInputError("Two hashes are required")
        h1 = hash1.strip().lower(); h2 = hash2.strip().lower()
        return {"hash1": h1, "hash2": h2, "match": h1 == h2, "length_match": len(h1) == len(h2),
                "hash1_length": len(h1), "hash2_length": len(h2)}

    def verify(self, text: str, expected_hash: str) -> dict:
        if not text or not expected_hash: raise InvalidInputError("Text and expected hash are required")
        expected = expected_hash.strip().lower(); data = text.encode("utf-8")
        algos = {32: [("md5", hashlib.md5)], 40: [("sha1", hashlib.sha1)],
                 56: [("sha224", hashlib.sha224)],
                 64: [("sha256", hashlib.sha256), ("sha3_256", hashlib.sha3_256)],
                 96: [("sha384", hashlib.sha384)],
                 128: [("sha512", hashlib.sha512), ("sha3_512", hashlib.sha3_512)]}
        candidates = algos.get(len(expected), [])
        matches = [{"algorithm": name, "computed": func(data).hexdigest(), "match": func(data).hexdigest() == expected} for name, func in candidates]
        return {"text_length": len(text), "expected_hash": expected, "expected_length": len(expected),
                "verified": any(m["match"] for m in matches),
                "matched_algorithm": next((m["algorithm"] for m in matches if m["match"]), None), "results": matches}
