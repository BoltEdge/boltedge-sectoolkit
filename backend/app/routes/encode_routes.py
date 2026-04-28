"""
SecToolkit 101 â€” Encode/Decode Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        from app.engines.encode.encode_engines import (
            Base64Engine, URLEncodeEngine, HTMLEntityEngine, HexEngine,
            BinaryEngine, ROT13Engine, ASCIIEngine, JWTDecoderEngine,
            UnicodeEngine, PunycodeEngine, MorseCodeEngine, CaesarCipherEngine,
            RegexTesterEngine, StringConverterEngine,
        )
        _map = {"base64": Base64Engine, "url_encode": URLEncodeEngine,
                "html_entity": HTMLEntityEngine, "hex": HexEngine,
                "binary": BinaryEngine, "rot13": ROT13Engine,
                "ascii": ASCIIEngine, "jwt": JWTDecoderEngine,
                "unicode": UnicodeEngine, "punycode": PunycodeEngine,
                "morse": MorseCodeEngine, "caesar": CaesarCipherEngine,
                "regex": RegexTesterEngine, "string": StringConverterEngine}
        if name in _map: _engines[name] = _map[name]()
    return _engines[name]

encode_bp = Blueprint("encode", __name__)

@encode_bp.route("/base64/encode", methods=["POST"])
@timed_tool("encode.base64_encode")
def base64_encode():
    target = get_target(); return _get_engine("base64").encode(target), target

@encode_bp.route("/base64/decode", methods=["POST"])
@timed_tool("encode.base64_decode")
def base64_decode():
    target = get_target(); return _get_engine("base64").decode(target), target

@encode_bp.route("/url/encode", methods=["POST"])
@timed_tool("encode.url_encode")
def url_encode():
    target = get_target(); return _get_engine("url_encode").encode(target), target

@encode_bp.route("/url/decode", methods=["POST"])
@timed_tool("encode.url_decode")
def url_decode():
    target = get_target(); return _get_engine("url_encode").decode(target), target

@encode_bp.route("/html/encode", methods=["POST"])
@timed_tool("encode.html_encode")
def html_encode():
    target = get_target(); return _get_engine("html_entity").encode(target), target

@encode_bp.route("/html/decode", methods=["POST"])
@timed_tool("encode.html_decode")
def html_decode():
    target = get_target(); return _get_engine("html_entity").decode(target), target

@encode_bp.route("/hex/encode", methods=["POST"])
@timed_tool("encode.hex_encode")
def hex_encode():
    target = get_target(); return _get_engine("hex").encode(target), target

@encode_bp.route("/hex/decode", methods=["POST"])
@timed_tool("encode.hex_decode")
def hex_decode():
    target = get_target(); return _get_engine("hex").decode(target), target

@encode_bp.route("/binary/encode", methods=["POST"])
@timed_tool("encode.binary_encode")
def binary_encode():
    target = get_target(); return _get_engine("binary").encode(target), target

@encode_bp.route("/binary/decode", methods=["POST"])
@timed_tool("encode.binary_decode")
def binary_decode():
    target = get_target(); return _get_engine("binary").decode(target), target

@encode_bp.route("/rot13", methods=["POST"])
@timed_tool("encode.rot13")
def rot13():
    target = get_target(); return _get_engine("rot13").transform(target), target

@encode_bp.route("/ascii/to-codes", methods=["POST"])
@timed_tool("encode.ascii_to_codes")
def ascii_to_codes():
    target = get_target(); return _get_engine("ascii").text_to_ascii(target), target

@encode_bp.route("/ascii/to-text", methods=["POST"])
@timed_tool("encode.ascii_to_text")
def ascii_to_text():
    target = get_target(); return _get_engine("ascii").ascii_to_text(target), target

@encode_bp.route("/jwt/decode", methods=["POST"])
@timed_tool("encode.jwt_decode")
def jwt_decode():
    target = get_target(); return _get_engine("jwt").decode(target), target

@encode_bp.route("/unicode/encode", methods=["POST"])
@timed_tool("encode.unicode_encode")
def unicode_encode():
    target = get_target(); return _get_engine("unicode").encode(target), target

@encode_bp.route("/unicode/decode", methods=["POST"])
@timed_tool("encode.unicode_decode")
def unicode_decode():
    target = get_target(); return _get_engine("unicode").decode(target), target

@encode_bp.route("/punycode/encode", methods=["POST"])
@timed_tool("encode.punycode_encode")
def punycode_encode():
    target = get_target(); return _get_engine("punycode").encode(target), target

@encode_bp.route("/punycode/decode", methods=["POST"])
@timed_tool("encode.punycode_decode")
def punycode_decode():
    target = get_target(); return _get_engine("punycode").decode(target), target

@encode_bp.route("/morse/encode", methods=["POST"])
@timed_tool("encode.morse_encode")
def morse_encode():
    target = get_target(); return _get_engine("morse").encode(target), target

@encode_bp.route("/morse/decode", methods=["POST"])
@timed_tool("encode.morse_decode")
def morse_decode():
    target = get_target(); return _get_engine("morse").decode(target), target

@encode_bp.route("/caesar/encrypt", methods=["POST"])
@timed_tool("encode.caesar_encrypt")
def caesar_encrypt():
    target = get_target(); options = get_options()
    return _get_engine("caesar").encrypt(target, shift=options.get("shift", 3)), target

@encode_bp.route("/caesar/decrypt", methods=["POST"])
@timed_tool("encode.caesar_decrypt")
def caesar_decrypt():
    target = get_target(); options = get_options()
    return _get_engine("caesar").decrypt(target, shift=options.get("shift", 3)), target

@encode_bp.route("/caesar/bruteforce", methods=["POST"])
@timed_tool("encode.caesar_bruteforce")
def caesar_bruteforce():
    target = get_target(); return _get_engine("caesar").brute_force(target), target

@encode_bp.route("/regex", methods=["POST"])
@timed_tool("encode.regex")
def regex_tester():
    target = get_target(); options = get_options()
    return _get_engine("regex").test(target, options.get("text", ""), flags=options.get("flags", "")), target

@encode_bp.route("/string", methods=["POST"])
@timed_tool("encode.string")
def string_converter():
    target = get_target(); return _get_engine("string").convert(target), target
