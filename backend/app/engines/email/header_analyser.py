"""
BoltEdge SecToolkit â€” Header Analyser Engine
"""
import re
from email.utils import parsedate_to_datetime
from app.utils.exceptions import EngineError, InvalidInputError


class HeaderAnalyserEngine:
    def analyse(self, headers: str) -> dict:
        if not headers or not headers.strip(): raise InvalidInputError("Empty headers")
        try:
            hops = self._parse_received(headers)
            auth = self._parse_auth_results(headers)
            key_headers = self._extract_key_headers(headers)
            return {"hops": hops, "hop_count": len(hops), "authentication": auth,
                    "key_headers": key_headers, "origin_ip": self._extract_origin_ip(hops)}
        except InvalidInputError: raise
        except Exception as e: raise EngineError(f"Header analysis failed: {str(e)}")

    def _parse_received(self, headers):
        received = re.findall(r"Received:\s*(.*?)(?=\nReceived:|\n[A-Z][\w-]*:|\Z)", headers, re.DOTALL | re.IGNORECASE)
        hops = []
        for i, raw in enumerate(received):
            raw_clean = " ".join(raw.split())
            hop = {"index": i + 1, "raw": raw_clean}
            from_match = re.search(r"from\s+([\w\.\-]+)", raw_clean, re.IGNORECASE)
            by_match = re.search(r"by\s+([\w\.\-]+)", raw_clean, re.IGNORECASE)
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", raw_clean)
            date_match = re.search(r";\s*(.+)$", raw_clean)
            hop["from"] = from_match.group(1) if from_match else None
            hop["by"] = by_match.group(1) if by_match else None
            hop["ip"] = ip_match.group(1) if ip_match else None
            if date_match:
                try: hop["timestamp"] = parsedate_to_datetime(date_match.group(1).strip()).isoformat()
                except Exception: hop["timestamp"] = date_match.group(1).strip()
            else: hop["timestamp"] = None
            hops.append(hop)
        return hops

    @staticmethod
    def _parse_auth_results(headers):
        auth = {"spf": None, "dkim": None, "dmarc": None}
        ar_match = re.search(r"Authentication-Results:\s*(.*?)(?=\n\S|\Z)", headers, re.DOTALL | re.IGNORECASE)
        if not ar_match: return auth
        ar = " ".join(ar_match.group(1).split())
        for key in ["spf", "dkim", "dmarc"]:
            m = re.search(rf"{key}=(pass|fail|softfail|neutral|none|temperror|permerror)", ar, re.IGNORECASE)
            auth[key] = m.group(1).lower() if m else None
        return auth

    @staticmethod
    def _extract_key_headers(headers):
        key = {}
        patterns = {"from": r"^From:\s*(.+)$", "to": r"^To:\s*(.+)$", "subject": r"^Subject:\s*(.+)$",
                     "date": r"^Date:\s*(.+)$", "message_id": r"^Message-ID:\s*(.+)$",
                     "return_path": r"^Return-Path:\s*(.+)$", "reply_to": r"^Reply-To:\s*(.+)$",
                     "x_mailer": r"^X-Mailer:\s*(.+)$"}
        for name, pattern in patterns.items():
            m = re.search(pattern, headers, re.MULTILINE | re.IGNORECASE)
            key[name] = m.group(1).strip() if m else None
        return key

    @staticmethod
    def _extract_origin_ip(hops):
        return hops[-1].get("ip") if hops else None
