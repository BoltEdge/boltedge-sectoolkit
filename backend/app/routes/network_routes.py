"""
BoltEdge SecToolkit â€” Network Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        from app.engines.network.network_engines import (
            StatusCheckerEngine, DNSLeakTestEngine, WhoisHistoryEngine,
            MACLookupEngine, HTTP2CheckEngine, HSTSCheckEngine,
            MTUCalculatorEngine, BandwidthCalculatorEngine)
        _map = {"status": StatusCheckerEngine, "dns_leak": DNSLeakTestEngine,
                "whois_history": WhoisHistoryEngine, "mac": MACLookupEngine,
                "http2": HTTP2CheckEngine, "hsts": HSTSCheckEngine,
                "mtu": MTUCalculatorEngine, "bandwidth": BandwidthCalculatorEngine}
        if name in _map: _engines[name] = _map[name]()
    return _engines[name]

network_bp = Blueprint("network", __name__)

@network_bp.route("/status", methods=["POST"])
@timed_tool("network.status")
def status_check():
    target = get_target(); return _get_engine("status").check(target), target

@network_bp.route("/dns-leak", methods=["POST"])
@timed_tool("network.dns_leak")
def dns_leak():
    target = get_target(); return _get_engine("dns_leak").test(target), target

@network_bp.route("/whois-history", methods=["POST"])
@timed_tool("network.whois_history")
def whois_history():
    target = get_target(); return _get_engine("whois_history").lookup(target), target

@network_bp.route("/mac", methods=["POST"])
@timed_tool("network.mac_lookup")
def mac_lookup():
    target = get_target(); return _get_engine("mac").lookup(target), target

@network_bp.route("/http2", methods=["POST"])
@timed_tool("network.http2")
def http2_check():
    target = get_target(); return _get_engine("http2").check(target), target

@network_bp.route("/hsts", methods=["POST"])
@timed_tool("network.hsts")
def hsts_check():
    target = get_target(); return _get_engine("hsts").check(target), target

@network_bp.route("/mtu", methods=["POST"])
@timed_tool("network.mtu")
def mtu_calc():
    options = get_options()
    return _get_engine("mtu").calculate(protocol=options.get("protocol", "ethernet"), overhead=options.get("overhead", 0)), "mtu"

@network_bp.route("/bandwidth", methods=["POST"])
@timed_tool("network.bandwidth")
def bandwidth_calc():
    options = get_options()
    return _get_engine("bandwidth").calculate(file_size_mb=options.get("file_size_mb"),
        bandwidth_mbps=options.get("bandwidth_mbps"), time_seconds=options.get("time_seconds")), "bandwidth"
