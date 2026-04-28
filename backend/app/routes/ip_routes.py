"""
SecToolkit 101 — IP Tool Routes

Endpoints: POST /api/ip/<tool>
Tools: 15 IP tools wired to their engines

All routes follow the pattern:
  1. Extract and validate target from request body
  2. Call engine method
  3. Return timed success/error response
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

# --- Engine Instances (lazy-loaded singletons) ---
_engines = {}


def _get_engine(name):
    """Lazy-load engine instances to avoid import-time DB/file access."""
    if name not in _engines:
        if name == "geolocation":
            from app.engines.ip.geolocation import GeolocationEngine
            _engines[name] = GeolocationEngine()
        elif name == "reputation":
            from app.engines.ip.reputation import ReputationEngine
            _engines[name] = ReputationEngine()
        elif name == "whois":
            from app.engines.ip.whois import WhoisEngine
            _engines[name] = WhoisEngine()
        elif name == "reverse_dns":
            from app.engines.ip.reverse_dns import ReverseDNSEngine
            _engines[name] = ReverseDNSEngine()
        elif name == "asn_lookup":
            from app.engines.ip.asn_lookup import ASNLookupEngine
            _engines[name] = ASNLookupEngine()
        elif name == "subnet_calculator":
            from app.engines.ip.subnet_calculator import SubnetCalculatorEngine
            _engines[name] = SubnetCalculatorEngine()
        elif name == "cidr_calculator":
            from app.engines.ip.cidr_calculator import CIDRCalculatorEngine
            _engines[name] = CIDRCalculatorEngine()
        elif name == "ip_range_generator":
            from app.engines.ip.ip_range_generator import IPRangeGeneratorEngine
            _engines[name] = IPRangeGeneratorEngine()
        elif name == "ptr_lookup":
            from app.engines.ip.ptr_lookup import PTRLookupEngine
            _engines[name] = PTRLookupEngine()
        elif name == "blacklist_check":
            from app.engines.ip.blacklist_check import BlacklistCheckEngine
            _engines[name] = BlacklistCheckEngine()
        elif name == "ip_history":
            from app.engines.ip.ip_history import IPHistoryEngine
            _engines[name] = IPHistoryEngine()
        elif name == "port_scanner":
            from app.engines.ip.port_scanner import PortScannerEngine
            _engines[name] = PortScannerEngine()
        elif name == "ping_test":
            from app.engines.ip.ping_test import PingTestEngine
            _engines[name] = PingTestEngine()
        elif name == "traceroute":
            from app.engines.ip.traceroute import TracerouteEngine
            _engines[name] = TracerouteEngine()
        elif name == "vpn_detection":
            from app.engines.ip.vpn_detection import VPNDetectionEngine
            _engines[name] = VPNDetectionEngine()
    return _engines[name]


# --- Blueprint ---
ip_bp = Blueprint("ip", __name__)


# ============================================================
# 1. IP Geolocation
# POST /api/ip/geolocation
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/geolocation", methods=["POST"])
@timed_tool("ip.geolocation")
def geolocation():
    target = get_target()
    engine = _get_engine("geolocation")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 2. IP Reputation
# POST /api/ip/reputation
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/reputation", methods=["POST"])
@timed_tool("ip.reputation")
def reputation():
    target = get_target()
    engine = _get_engine("reputation")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 3. IP WHOIS
# POST /api/ip/whois
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/whois", methods=["POST"])
@timed_tool("ip.whois")
def whois():
    target = get_target()
    engine = _get_engine("whois")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 4. Reverse DNS
# POST /api/ip/reverse-dns
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/reverse-dns", methods=["POST"])
@timed_tool("ip.reverse_dns")
def reverse_dns():
    target = get_target()
    engine = _get_engine("reverse_dns")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 5. ASN Lookup
# POST /api/ip/asn
# Body: { "target": "8.8.8.8" } or { "target": "AS15169" }
# ============================================================
@ip_bp.route("/asn", methods=["POST"])
@timed_tool("ip.asn_lookup")
def asn_lookup():
    target = get_target()
    engine = _get_engine("asn_lookup")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 6. Subnet Calculator
# POST /api/ip/subnet-calculator
# Body: { "target": "192.168.1.0/24" }
# ============================================================
@ip_bp.route("/subnet-calculator", methods=["POST"])
@timed_tool("ip.subnet_calculator")
def subnet_calculator():
    target = get_target()
    engine = _get_engine("subnet_calculator")
    result = engine.calculate(target)
    return result, target


# ============================================================
# 7. CIDR Calculator
# POST /api/ip/cidr-calculator
# Body: { "target": "/24" } or { "target": "255.255.255.0" }
# ============================================================
@ip_bp.route("/cidr-calculator", methods=["POST"])
@timed_tool("ip.cidr_calculator")
def cidr_calculator():
    target = get_target()
    engine = _get_engine("cidr_calculator")
    result = engine.convert(target)
    return result, target


# ============================================================
# 7b. CIDR Compare
# POST /api/ip/cidr-compare
# Body: { "target": "10.0.0.0/8", "options": { "compare_to": "10.1.0.0/16" } }
# ============================================================
@ip_bp.route("/cidr-compare", methods=["POST"])
@timed_tool("ip.cidr_compare")
def cidr_compare():
    target = get_target()
    options = get_options()
    compare_to = options.get("compare_to", "")
    if not compare_to:
        from app.utils.exceptions import MissingInputError
        raise MissingInputError("options.compare_to")
    engine = _get_engine("cidr_calculator")
    result = engine.compare(target, compare_to)
    return result, target


# ============================================================
# 7c. Subnet Table
# GET /api/ip/subnet-table
# ============================================================
@ip_bp.route("/subnet-table", methods=["GET"])
@timed_tool("ip.subnet_table")
def subnet_table():
    engine = _get_engine("cidr_calculator")
    result = engine.subnet_table()
    return {"table": result}, "all"


# ============================================================
# 8. IP Range Generator
# POST /api/ip/range-generator
# Body: { "target": "192.168.1.0/24" } or { "target": "1.1.1.1-1.1.1.50" }
# ============================================================
@ip_bp.route("/range-generator", methods=["POST"])
@timed_tool("ip.range_generator")
def range_generator():
    target = get_target()
    options = get_options()
    limit = options.get("limit")
    engine = _get_engine("ip_range_generator")
    result = engine.generate(target, limit=limit)
    return result, target


# ============================================================
# 9. PTR Lookup
# POST /api/ip/ptr
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/ptr", methods=["POST"])
@timed_tool("ip.ptr_lookup")
def ptr_lookup():
    target = get_target()
    engine = _get_engine("ptr_lookup")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 10. Blacklist Check
# POST /api/ip/blacklist
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/blacklist", methods=["POST"])
@timed_tool("ip.blacklist_check")
def blacklist_check():
    target = get_target()
    engine = _get_engine("blacklist_check")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 11. IP History
# POST /api/ip/history
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/history", methods=["POST"])
@timed_tool("ip.ip_history")
def ip_history():
    target = get_target()
    engine = _get_engine("ip_history")
    result = engine.lookup(target)
    return result, target


# ============================================================
# 12. Port Scanner
# POST /api/ip/port-scan
# Body: { "target": "8.8.8.8", "options": { "ports": "80,443,22" } }
# ============================================================
@ip_bp.route("/port-scan", methods=["POST"])
@timed_tool("ip.port_scanner")
def port_scan():
    target = get_target()
    options = get_options()
    ports = options.get("ports")
    engine = _get_engine("port_scanner")
    result = engine.scan(target, ports=ports)
    return result, target


# ============================================================
# 13. Ping Test
# POST /api/ip/ping
# Body: { "target": "8.8.8.8", "options": { "count": 4 } }
# ============================================================
@ip_bp.route("/ping", methods=["POST"])
@timed_tool("ip.ping_test")
def ping_test():
    target = get_target()
    options = get_options()
    count = options.get("count")
    engine = _get_engine("ping_test")
    result = engine.ping(target, count=count)
    return result, target


# ============================================================
# 14. Traceroute
# POST /api/ip/traceroute
# Body: { "target": "8.8.8.8", "options": { "max_hops": 30 } }
# ============================================================
@ip_bp.route("/traceroute", methods=["POST"])
@timed_tool("ip.traceroute")
def traceroute():
    target = get_target()
    options = get_options()
    max_hops = options.get("max_hops")
    engine = _get_engine("traceroute")
    result = engine.trace(target, max_hops=max_hops)
    return result, target


# ============================================================
# 15. VPN Detection
# POST /api/ip/vpn-detection
# Body: { "target": "8.8.8.8" }
# ============================================================
@ip_bp.route("/vpn-detection", methods=["POST"])
@timed_tool("ip.vpn_detection")
def vpn_detection():
    target = get_target()
    engine = _get_engine("vpn_detection")
    result = engine.detect(target)
    return result, target