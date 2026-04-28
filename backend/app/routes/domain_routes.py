"""
SecToolkit 101 â€” Domain Tool Routes

Endpoints: POST /api/domain/<tool>
Tools: 12 Domain tools wired to their engines
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}


def _get_engine(name):
    if name not in _engines:
        if name == "dns_lookup":
            from app.engines.domain.dns_lookup import DNSLookupEngine
            _engines[name] = DNSLookupEngine()
        elif name == "domain_whois":
            from app.engines.domain.domain_whois import DomainWhoisEngine
            _engines[name] = DomainWhoisEngine()
        elif name == "subdomain_finder":
            from app.engines.domain.subdomain_finder import SubdomainFinderEngine
            _engines[name] = SubdomainFinderEngine()
        elif name == "dns_propagation":
            from app.engines.domain.dns_propagation import DNSPropagationEngine
            _engines[name] = DNSPropagationEngine()
        elif name == "mx_records":
            from app.engines.domain.mx_records import MXRecordsEngine
            _engines[name] = MXRecordsEngine()
        elif name == "ns_records":
            from app.engines.domain.ns_records import NSRecordsEngine
            _engines[name] = NSRecordsEngine()
        elif name == "txt_records":
            from app.engines.domain.txt_records import TXTRecordsEngine
            _engines[name] = TXTRecordsEngine()
        elif name == "domain_age":
            from app.engines.domain.domain_age import DomainAgeEngine
            _engines[name] = DomainAgeEngine()
        elif name == "reverse_ip":
            from app.engines.domain.reverse_ip import ReverseIPEngine
            _engines[name] = ReverseIPEngine()
        elif name == "dnssec_validator":
            from app.engines.domain.dnssec_validator import DNSSECValidatorEngine
            _engines[name] = DNSSECValidatorEngine()
        elif name == "zone_transfer":
            from app.engines.domain.zone_transfer import ZoneTransferEngine
            _engines[name] = ZoneTransferEngine()
        elif name == "domain_reputation":
            from app.engines.domain.domain_reputation import DomainReputationEngine
            _engines[name] = DomainReputationEngine()
    return _engines[name]


domain_bp = Blueprint("domain", __name__)


@domain_bp.route("/dns-lookup", methods=["POST"])
@timed_tool("domain.dns_lookup")
def dns_lookup():
    target = get_target()
    options = get_options()
    record_type = options.get("record_type")
    engine = _get_engine("dns_lookup")
    result = engine.lookup(target, record_type=record_type)
    return result, target


@domain_bp.route("/whois", methods=["POST"])
@timed_tool("domain.whois")
def domain_whois():
    target = get_target()
    engine = _get_engine("domain_whois")
    result = engine.lookup(target)
    return result, target


@domain_bp.route("/subdomains", methods=["POST"])
@timed_tool("domain.subdomain_finder")
def subdomain_finder():
    target = get_target()
    engine = _get_engine("subdomain_finder")
    result = engine.find(target)
    return result, target


@domain_bp.route("/propagation", methods=["POST"])
@timed_tool("domain.dns_propagation")
def dns_propagation():
    target = get_target()
    options = get_options()
    record_type = options.get("record_type", "A")
    engine = _get_engine("dns_propagation")
    result = engine.check(target, record_type=record_type)
    return result, target


@domain_bp.route("/mx", methods=["POST"])
@timed_tool("domain.mx_records")
def mx_records():
    target = get_target()
    engine = _get_engine("mx_records")
    result = engine.lookup(target)
    return result, target


@domain_bp.route("/ns", methods=["POST"])
@timed_tool("domain.ns_records")
def ns_records():
    target = get_target()
    engine = _get_engine("ns_records")
    result = engine.lookup(target)
    return result, target


@domain_bp.route("/txt", methods=["POST"])
@timed_tool("domain.txt_records")
def txt_records():
    target = get_target()
    engine = _get_engine("txt_records")
    result = engine.lookup(target)
    return result, target


@domain_bp.route("/age", methods=["POST"])
@timed_tool("domain.age")
def domain_age():
    target = get_target()
    engine = _get_engine("domain_age")
    result = engine.lookup(target)
    return result, target


@domain_bp.route("/reverse-ip", methods=["POST"])
@timed_tool("domain.reverse_ip")
def reverse_ip():
    target = get_target()
    engine = _get_engine("reverse_ip")
    result = engine.lookup(target)
    return result, target


@domain_bp.route("/dnssec", methods=["POST"])
@timed_tool("domain.dnssec")
def dnssec_validator():
    target = get_target()
    engine = _get_engine("dnssec_validator")
    result = engine.validate(target)
    return result, target


@domain_bp.route("/zone-transfer", methods=["POST"])
@timed_tool("domain.zone_transfer")
def zone_transfer():
    target = get_target()
    engine = _get_engine("zone_transfer")
    result = engine.test(target)
    return result, target


@domain_bp.route("/reputation", methods=["POST"])
@timed_tool("domain.reputation")
def domain_reputation():
    target = get_target()
    engine = _get_engine("domain_reputation")
    result = engine.lookup(target)
    return result, target
