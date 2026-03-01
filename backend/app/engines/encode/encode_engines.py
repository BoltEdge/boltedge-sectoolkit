"""
BoltEdge SecToolkit â€” Encode/Decode Engines (14 tools)
All encode/decode tools are client-side capable.
"""
import base64
import binascii
import html
import json
import re
import urllib.parse
from app.utils.exceptions import InvalidInputError, EngineError


# 1. Base64
class Base64Engine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        return {"input": text, "encoded": base64.b64encode(text.encode("utf-8")).decode("ascii"), "mode": "encode"}

    def decode(self, text):
        if not text: raise InvalidInputError("Empty input")
        try: return {"input": text.strip(), "decoded": base64.b64decode(text.strip()).decode("utf-8", errors="replace"), "mode": "decode"}
        except Exception as e: raise InvalidInputError(f"Invalid Base64: {str(e)}")


# 2. URL Encode
class URLEncodeEngine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        return {"input": text, "encoded": urllib.parse.quote(text, safe=""),
                "encoded_plus": urllib.parse.quote_plus(text), "mode": "encode"}

    def decode(self, text):
        if not text: raise InvalidInputError("Empty input")
        return {"input": text, "decoded": urllib.parse.unquote(text),
                "decoded_plus": urllib.parse.unquote_plus(text), "mode": "decode"}


# 3. HTML Entity
class HTMLEntityEngine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        return {"input": text, "encoded": html.escape(text, quote=True),
                "numeric_entities": "".join(f"&#{ord(c)};" for c in text), "mode": "encode"}

    def decode(self, text):
        if not text: raise InvalidInputError("Empty input")
        return {"input": text, "decoded": html.unescape(text), "mode": "decode"}


# 4. Hex
class HexEngine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        hex_str = text.encode("utf-8").hex()
        return {"input": text, "hex": hex_str,
                "hex_spaced": " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)),
                "hex_prefixed": " ".join(f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2)), "mode": "encode"}

    def decode(self, text):
        if not text: raise InvalidInputError("Empty input")
        clean = text.replace(" ", "").replace("0x", "").replace("\\x", "")
        try: return {"input": text, "decoded": bytes.fromhex(clean).decode("utf-8", errors="replace"), "mode": "decode"}
        except ValueError as e: raise InvalidInputError(f"Invalid hex: {str(e)}")


# 5. Binary
class BinaryEngine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        return {"input": text, "binary": " ".join(f"{b:08b}" for b in text.encode("utf-8")), "mode": "encode"}

    def decode(self, text):
        if not text: raise InvalidInputError("Empty input")
        clean = text.replace(" ", "")
        if not all(c in "01" for c in clean): raise InvalidInputError("Input must be binary (0s and 1s)")
        try:
            chunks = [clean[i:i+8] for i in range(0, len(clean), 8)]
            return {"input": text, "decoded": bytes(int(b, 2) for b in chunks).decode("utf-8", errors="replace"), "mode": "decode"}
        except Exception as e: raise InvalidInputError(f"Invalid binary: {str(e)}")


# 6. ROT13
class ROT13Engine:
    def transform(self, text):
        if text is None: raise InvalidInputError("Empty input")
        import codecs
        return {"input": text, "output": codecs.encode(text, "rot_13"), "algorithm": "ROT13"}


# 7. ASCII
class ASCIIEngine:
    def text_to_ascii(self, text):
        if text is None: raise InvalidInputError("Empty input")
        codes = [ord(c) for c in text]
        return {"input": text, "ascii_codes": codes,
                "decimal": " ".join(str(c) for c in codes),
                "hex": " ".join(f"{c:02x}" for c in codes),
                "octal": " ".join(f"{c:03o}" for c in codes)}

    def ascii_to_text(self, codes):
        if not codes: raise InvalidInputError("Empty input")
        try:
            nums = [int(n.strip()) for n in re.split(r"[,\s]+", codes.strip()) if n.strip()]
            return {"input": codes, "text": "".join(chr(n) for n in nums)}
        except (ValueError, OverflowError) as e: raise InvalidInputError(f"Invalid ASCII codes: {str(e)}")


# 8. JWT Decoder
class JWTDecoderEngine:
    def decode(self, token):
        if not token: raise InvalidInputError("Empty token")
        token = token.strip()
        parts = token.split(".")
        if len(parts) != 3: raise InvalidInputError("Invalid JWT â€” must have 3 parts separated by dots")
        try:
            header = self._decode_part(parts[0])
            payload = self._decode_part(parts[1])
            import time
            now = int(time.time())
            exp = payload.get("exp")
            return {"token": token[:50] + "..." if len(token) > 50 else token,
                    "header": header, "payload": payload, "signature": parts[2][:20] + "...",
                    "algorithm": header.get("alg"), "type": header.get("typ"),
                    "issued_at": payload.get("iat"), "expires_at": exp, "not_before": payload.get("nbf"),
                    "is_expired": exp < now if exp else None}
        except InvalidInputError: raise
        except Exception as e: raise InvalidInputError(f"Failed to decode JWT: {str(e)}")

    @staticmethod
    def _decode_part(part):
        padding = 4 - len(part) % 4
        if padding != 4: part += "=" * padding
        return json.loads(base64.urlsafe_b64decode(part))


# 9. Unicode
class UnicodeEngine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        return {"input": text, "unicode_escaped": text.encode("unicode_escape").decode("ascii"),
                "code_points": [f"U+{ord(c):04X}" for c in text],
                "html_entities": "".join(f"&#x{ord(c):X};" for c in text)}

    def decode(self, text):
        if not text: raise InvalidInputError("Empty input")
        try: return {"input": text, "decoded": text.encode("utf-8").decode("unicode_escape")}
        except Exception:
            result = re.sub(r"U\+([0-9A-Fa-f]{4,6})", lambda m: chr(int(m.group(1), 16)), text)
            return {"input": text, "decoded": result}


# 10. Punycode
class PunycodeEngine:
    def encode(self, domain):
        if not domain: raise InvalidInputError("Empty input")
        try: return {"input": domain, "punycode": domain.encode("idna").decode("ascii"), "mode": "encode"}
        except Exception as e: raise InvalidInputError(f"Cannot encode to Punycode: {str(e)}")

    def decode(self, domain):
        if not domain: raise InvalidInputError("Empty input")
        try: return {"input": domain, "decoded": domain.encode("ascii").decode("idna"), "mode": "decode"}
        except Exception as e: raise InvalidInputError(f"Cannot decode Punycode: {str(e)}")


# 11. Morse Code
_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "!": "-.-.--", "/": "-..-.", "@": ".--.-.",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}

class MorseCodeEngine:
    def encode(self, text):
        if text is None: raise InvalidInputError("Empty input")
        result = []
        for c in text.upper():
            if c == " ": result.append("/")
            elif c in _MORSE: result.append(_MORSE[c])
        return {"input": text, "morse": " ".join(result), "mode": "encode"}

    def decode(self, morse):
        if not morse: raise InvalidInputError("Empty input")
        words = morse.strip().split(" / ")
        result = []
        for word in words:
            chars = word.strip().split(" ")
            result.append("".join(_MORSE_REV.get(c, "?") for c in chars if c))
        return {"input": morse, "text": " ".join(result), "mode": "decode"}


# 12. Caesar Cipher
class CaesarCipherEngine:
    def encrypt(self, text, shift=3):
        if text is None: raise InvalidInputError("Empty input")
        return {"input": text, "output": self._shift(text, shift), "shift": shift, "mode": "encrypt"}

    def decrypt(self, text, shift=3):
        if not text: raise InvalidInputError("Empty input")
        return {"input": text, "output": self._shift(text, -shift), "shift": shift, "mode": "decrypt"}

    def brute_force(self, text):
        if not text: raise InvalidInputError("Empty input")
        return {"input": text, "results": [{"shift": s, "text": self._shift(text, -s)} for s in range(1, 26)]}

    @staticmethod
    def _shift(text, shift):
        result = []
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else: result.append(c)
        return "".join(result)


# 13. Regex Tester
class RegexTesterEngine:
    def test(self, pattern, text, flags=""):
        if not pattern: raise InvalidInputError("Pattern is required")
        if text is None: raise InvalidInputError("Text is required")
        flag_map = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}
        compiled_flags = 0
        for f in flags:
            if f in flag_map: compiled_flags |= flag_map[f]
        try: compiled = re.compile(pattern, compiled_flags)
        except re.error as e: raise InvalidInputError(f"Invalid regex: {str(e)}")
        matches = []
        for m in compiled.finditer(text):
            info = {"match": m.group(), "start": m.start(), "end": m.end(), "groups": list(m.groups())}
            if m.groupdict(): info["named_groups"] = m.groupdict()
            matches.append(info)
        return {"pattern": pattern, "flags": flags, "text_length": len(text),
                "match_count": len(matches), "matches": matches, "full_match": bool(compiled.fullmatch(text))}


# 14. String Converter
class StringConverterEngine:
    def convert(self, text):
        if text is None: raise InvalidInputError("Empty input")
        words = text.split()
        return {"input": text, "lowercase": text.lower(), "uppercase": text.upper(),
                "title_case": text.title(),
                "sentence_case": text[0].upper() + text[1:].lower() if text else "",
                "camel_case": words[0].lower() + "".join(w.capitalize() for w in words[1:]) if words else "",
                "pascal_case": "".join(w.capitalize() for w in words),
                "snake_case": "_".join(w.lower() for w in words),
                "kebab_case": "-".join(w.lower() for w in words),
                "constant_case": "_".join(w.upper() for w in words),
                "dot_case": ".".join(w.lower() for w in words),
                "reversed": text[::-1], "char_count": len(text), "word_count": len(words)}
