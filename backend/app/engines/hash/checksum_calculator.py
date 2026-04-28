"""
SecToolkit 101 â€” Checksum Calculator Engine
"""
import hashlib
import binascii
import base64
from app.utils.exceptions import InvalidInputError


class ChecksumCalculatorEngine:
    def calculate(self, data: str, is_base64: bool = False) -> dict:
        if not data: raise InvalidInputError("Empty input")
        if is_base64:
            try: raw = base64.b64decode(data)
            except Exception: raise InvalidInputError("Invalid base64 data")
        else: raw = data.encode("utf-8")
        crc32 = binascii.crc32(raw) & 0xFFFFFFFF
        return {"data_size": len(raw), "is_base64": is_base64,
                "checksums": {"md5": hashlib.md5(raw).hexdigest(), "sha1": hashlib.sha1(raw).hexdigest(),
                              "sha256": hashlib.sha256(raw).hexdigest(), "sha512": hashlib.sha512(raw).hexdigest(),
                              "crc32": format(crc32, "08x")}}
