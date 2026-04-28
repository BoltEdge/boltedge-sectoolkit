"""
SecToolkit 101 â€” URL Parser Engine
"""
from urllib.parse import urlparse, parse_qs
from app.utils.exceptions import InvalidInputError


class URLParserEngine:
    def parse(self, target: str) -> dict:
        if not target or not target.strip(): raise InvalidInputError("Empty input")
        target = target.strip()
        if not target.startswith(("http://", "https://", "ftp://", "ftps://")):
            target = f"https://{target}"
        try: parsed = urlparse(target)
        except Exception as e: raise InvalidInputError(f"Could not parse URL: {str(e)}")
        query_params = parse_qs(parsed.query, keep_blank_values=True) if parsed.query else {}
        default_ports = {"http": 80, "https": 443, "ftp": 21}
        return {
            "input": target, "scheme": parsed.scheme, "hostname": parsed.hostname,
            "port": parsed.port, "effective_port": parsed.port or default_ports.get(parsed.scheme),
            "path": parsed.path or "/", "query": parsed.query, "fragment": parsed.fragment,
            "username": parsed.username, "password": "***" if parsed.password else None,
            "netloc": parsed.netloc, "query_params": query_params,
            "query_param_count": len(query_params),
            "path_segments": [s for s in parsed.path.split("/") if s],
            "is_secure": parsed.scheme in ("https", "ftps"),
            "has_auth": parsed.username is not None,
            "has_query": bool(parsed.query), "has_fragment": bool(parsed.fragment),
        }
