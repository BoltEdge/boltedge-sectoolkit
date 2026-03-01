"""
BoltEdge SecToolkit â€” Hash Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        if name == "generator":
            from app.engines.hash.hash_generator import HashGeneratorEngine; _engines[name] = HashGeneratorEngine()
        elif name == "identifier":
            from app.engines.hash.hash_identifier import HashIdentifierEngine; _engines[name] = HashIdentifierEngine()
        elif name == "comparer":
            from app.engines.hash.hash_comparer import HashComparerEngine; _engines[name] = HashComparerEngine()
        elif name == "hmac":
            from app.engines.hash.hmac_generator import HMACGeneratorEngine; _engines[name] = HMACGeneratorEngine()
        elif name == "checksum":
            from app.engines.hash.checksum_calculator import ChecksumCalculatorEngine; _engines[name] = ChecksumCalculatorEngine()
        elif name == "lookup":
            from app.engines.hash.hash_lookup import HashLookupEngine; _engines[name] = HashLookupEngine()
        elif name == "bcrypt":
            from app.engines.hash.bcrypt_generator import BcryptGeneratorEngine; _engines[name] = BcryptGeneratorEngine()
        elif name == "scrypt":
            from app.engines.hash.scrypt_generator import ScryptGeneratorEngine; _engines[name] = ScryptGeneratorEngine()
        elif name == "argon2":
            from app.engines.hash.argon2_generator import Argon2GeneratorEngine; _engines[name] = Argon2GeneratorEngine()
        elif name == "pbkdf2":
            from app.engines.hash.pbkdf2_generator import PBKDF2GeneratorEngine; _engines[name] = PBKDF2GeneratorEngine()
        elif name == "md5":
            from app.engines.hash.md5_generator import MD5GeneratorEngine; _engines[name] = MD5GeneratorEngine()
        elif name == "sha":
            from app.engines.hash.sha_generator import SHAGeneratorEngine; _engines[name] = SHAGeneratorEngine()
        elif name == "reverser":
            from app.engines.hash.hash_reverser import HashReverserEngine; _engines[name] = HashReverserEngine()
    return _engines[name]

hash_bp = Blueprint("hash", __name__)

@hash_bp.route("/generate", methods=["POST"])
@timed_tool("hash.generator")
def hash_generate():
    target = get_target(); return _get_engine("generator").generate(target), target

@hash_bp.route("/identify", methods=["POST"])
@timed_tool("hash.identifier")
def hash_identify():
    target = get_target(); return _get_engine("identifier").identify(target), target

@hash_bp.route("/compare", methods=["POST"])
@timed_tool("hash.comparer")
def hash_compare():
    target = get_target(); options = get_options()
    return _get_engine("comparer").compare(target, options.get("hash2", "")), target

@hash_bp.route("/verify", methods=["POST"])
@timed_tool("hash.verify")
def hash_verify():
    target = get_target(); options = get_options()
    return _get_engine("comparer").verify(target, options.get("expected_hash", "")), target

@hash_bp.route("/hmac", methods=["POST"])
@timed_tool("hash.hmac")
def hmac_generate():
    target = get_target(); options = get_options()
    return _get_engine("hmac").generate(target, options.get("key", ""), options.get("algorithm", "sha256")), target

@hash_bp.route("/checksum", methods=["POST"])
@timed_tool("hash.checksum")
def checksum():
    target = get_target(); options = get_options()
    return _get_engine("checksum").calculate(target, is_base64=options.get("is_base64", False)), target

@hash_bp.route("/lookup", methods=["POST"])
@timed_tool("hash.lookup")
def hash_lookup():
    target = get_target(); return _get_engine("lookup").lookup(target), target

@hash_bp.route("/bcrypt", methods=["POST"])
@timed_tool("hash.bcrypt")
def bcrypt_generate():
    target = get_target(); options = get_options()
    return _get_engine("bcrypt").generate(target, rounds=options.get("rounds", 12)), target

@hash_bp.route("/bcrypt/verify", methods=["POST"])
@timed_tool("hash.bcrypt_verify")
def bcrypt_verify():
    target = get_target(); options = get_options()
    return _get_engine("bcrypt").verify(target, options.get("hash", "")), target

@hash_bp.route("/scrypt", methods=["POST"])
@timed_tool("hash.scrypt")
def scrypt_generate():
    target = get_target(); return _get_engine("scrypt").generate(target), target

@hash_bp.route("/argon2", methods=["POST"])
@timed_tool("hash.argon2")
def argon2_generate():
    target = get_target(); return _get_engine("argon2").generate(target), target

@hash_bp.route("/pbkdf2", methods=["POST"])
@timed_tool("hash.pbkdf2")
def pbkdf2_generate():
    target = get_target(); options = get_options()
    return _get_engine("pbkdf2").generate(target, iterations=options.get("iterations", 100000)), target

@hash_bp.route("/md5", methods=["POST"])
@timed_tool("hash.md5")
def md5_generate():
    target = get_target(); return _get_engine("md5").generate(target), target

@hash_bp.route("/sha", methods=["POST"])
@timed_tool("hash.sha")
def sha_generate():
    target = get_target(); options = get_options()
    return _get_engine("sha").generate(target, variant=options.get("variant")), target

@hash_bp.route("/reverse", methods=["POST"])
@timed_tool("hash.reverser")
def hash_reverse():
    target = get_target(); return _get_engine("reverser").reverse(target), target
