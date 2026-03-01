"""
BoltEdge SecToolkit â€” Password Engines (5 tools)
"""
import secrets
import string
import math
import hashlib
import re
from app.utils.exceptions import InvalidInputError, EngineError


# 1. Password Generator
class PasswordGeneratorEngine:
    def generate(self, length=16, uppercase=True, lowercase=True, digits=True, symbols=True, count=1, exclude=""):
        length = max(4, min(length, 128)); count = max(1, min(count, 20))
        charset = ""
        if uppercase: charset += string.ascii_uppercase
        if lowercase: charset += string.ascii_lowercase
        if digits: charset += string.digits
        if symbols: charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if exclude: charset = "".join(c for c in charset if c not in exclude)
        if not charset: raise InvalidInputError("No characters available")
        passwords = ["".join(secrets.choice(charset) for _ in range(length)) for _ in range(count)]
        entropy = length * math.log2(len(charset))
        return {"passwords": passwords, "length": length, "charset_size": len(charset),
                "entropy_bits": round(entropy, 1),
                "settings": {"uppercase": uppercase, "lowercase": lowercase, "digits": digits, "symbols": symbols}}


# 2. Password Strength
class PasswordStrengthEngine:
    def analyse(self, password):
        if not password: raise InvalidInputError("Password is required")
        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
        charset = (26 if has_upper else 0) + (26 if has_lower else 0) + (10 if has_digit else 0) + (32 if has_symbol else 0)
        entropy = length * math.log2(charset) if charset > 0 else 0
        issues = []
        if length < 8: issues.append("Too short â€” use at least 8 characters")
        if length < 12: issues.append("Consider using 12+ characters")
        if not has_upper: issues.append("No uppercase letters")
        if not has_lower: issues.append("No lowercase letters")
        if not has_digit: issues.append("No digits")
        if not has_symbol: issues.append("No symbols")
        if re.search(r"(.)\1{2,}", password): issues.append("Contains repeated characters")
        if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()): issues.append("Contains sequential characters")
        score = min(100, int(entropy))
        if len(issues) > 3: score = max(score - 20, 0)
        strength = "very_strong" if score >= 80 else ("strong" if score >= 60 else ("moderate" if score >= 40 else ("weak" if score >= 20 else "very_weak")))
        return {"length": length, "entropy_bits": round(entropy, 1), "charset_size": charset,
                "score": score, "strength": strength,
                "composition": {"uppercase": has_upper, "lowercase": has_lower, "digits": has_digit, "symbols": has_symbol},
                "issues": issues, "crack_time_estimate": self._crack_time(entropy)}

    @staticmethod
    def _crack_time(entropy):
        seconds = (2 ** entropy) / 10_000_000_000
        if seconds < 1: return "instant"
        if seconds < 60: return f"{int(seconds)} seconds"
        if seconds < 3600: return f"{int(seconds / 60)} minutes"
        if seconds < 86400: return f"{int(seconds / 3600)} hours"
        if seconds < 31536000: return f"{int(seconds / 86400)} days"
        years = seconds / 31536000
        if years < 1000: return f"{int(years)} years"
        if years < 1e6: return f"{int(years / 1000)}K years"
        return f"{years:.0e} years"


# 3. Passphrase Generator
_WORDLIST = [
    "correct", "horse", "battery", "staple", "mountain", "river", "forest",
    "ocean", "thunder", "crystal", "shadow", "phoenix", "dragon", "falcon",
    "silver", "golden", "copper", "diamond", "emerald", "sapphire",
    "ancient", "brave", "clever", "daring", "eager", "fierce", "gentle",
    "humble", "jolly", "kindly", "mighty", "noble", "proud", "quiet",
    "rapid", "silent", "tender", "unique", "vivid", "warm", "zealous",
    "arrow", "bridge", "castle", "dawn", "ember", "flame", "garden",
    "harbor", "island", "jungle", "knight", "lantern", "meadow",
    "north", "orbit", "palace", "quest", "ridge", "storm", "tower",
    "valley", "whisper", "zenith", "anchor", "beacon", "canyon",
    "drift", "echo", "frost", "glacier", "haven", "ivory", "jasper",
]

class PassphraseGeneratorEngine:
    def generate(self, words=4, separator="-", capitalize=False, add_number=False):
        words = max(3, min(words, 10))
        chosen = [secrets.choice(_WORDLIST) for _ in range(words)]
        if capitalize: chosen = [w.capitalize() for w in chosen]
        passphrase = separator.join(chosen)
        if add_number: passphrase += separator + str(secrets.randbelow(100))
        entropy = words * math.log2(len(_WORDLIST))
        if add_number: entropy += math.log2(100)
        return {"passphrase": passphrase, "word_count": words, "separator": separator,
                "entropy_bits": round(entropy, 1), "length": len(passphrase), "wordlist_size": len(_WORDLIST)}


# 4. Breach Check
class BreachCheckEngine:
    def __init__(self, db=None):
        self.db = db

    def check(self, password):
        if not password: raise InvalidInputError("Password is required")
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]; suffix = sha1[5:]
        count = self._check_local(prefix, suffix)
        return {"hash_prefix": prefix, "breached": count > 0, "breach_count": count,
                "message": f"Found in {count} breaches" if count > 0 else "Not found in known breaches",
                "recommendation": "Change this password immediately" if count > 0 else "Password not found in breach databases"}

    def _check_local(self, prefix, suffix):
        try:
            from app.models import BreachedHash; from app import db as app_db; db = self.db or app_db
            r = db.session.query(BreachedHash).filter(BreachedHash.prefix == prefix, BreachedHash.suffix == suffix).first()
            return r.count if r else 0
        except Exception: return 0


# 5. Entropy Calculator
class EntropyCalculatorEngine:
    def calculate(self, text):
        if not text: raise InvalidInputError("Input is required")
        length = len(text); freq = {}
        for c in text: freq[c] = freq.get(c, 0) + 1
        shannon = sum(-((count / length) * math.log2(count / length)) for count in freq.values())
        total = shannon * length
        charset_size = len(set(text))
        max_entropy = math.log2(charset_size) * length if charset_size > 1 else 0
        return {"text_length": length, "unique_chars": charset_size,
                "shannon_entropy_per_char": round(shannon, 4), "total_entropy_bits": round(total, 2),
                "max_possible_entropy": round(max_entropy, 2),
                "efficiency": round((total / max_entropy) * 100, 1) if max_entropy > 0 else 0,
                "character_frequencies": {c: count for c, count in sorted(freq.items(), key=lambda x: -x[1])[:20]},
                "randomness": "high" if shannon > 4 else ("medium" if shannon > 3 else "low")}
