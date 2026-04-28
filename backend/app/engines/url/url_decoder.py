"""
SecToolkit 101 â€” URL Decoder Engine
"""
from urllib.parse import unquote, unquote_plus, urlparse, parse_qs
from app.utils.exceptions import InvalidInputError


class URLDecoderEngine:
    def decode(self, target: str) -> dict:
        if not target or not target.strip(): raise InvalidInputError("Empty input")
        target = target.strip()
        layers = [target]
        current = target
        for _ in range(10):
            decoded = unquote(current)
            if decoded == current: break
            layers.append(decoded); current = decoded
        plus_decoded = unquote_plus(target)
        parsed = None; query_params = None
        try:
            p = urlparse(current)
            if p.scheme and p.hostname:
                parsed = {"scheme": p.scheme, "hostname": p.hostname, "port": p.port,
                          "path": p.path, "query": p.query, "fragment": p.fragment}
                query_params = parse_qs(p.query) if p.query else None
        except Exception: pass
        return {"input": target, "decoded": current, "plus_decoded": plus_decoded,
                "encoding_layers": len(layers) - 1, "layers": layers,
                "parsed_url": parsed, "query_params": query_params}
