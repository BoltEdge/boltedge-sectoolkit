"""
SecToolkit 101 â€” SSL Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        if name == "certificate_checker":
            from app.engines.ssl.ssl_certificate_checker import SSLCertificateCheckerEngine
            _engines[name] = SSLCertificateCheckerEngine()
        elif name == "ssl_labs":
            from app.engines.ssl.ssl_labs_test import SSLLabsTestEngine
            _engines[name] = SSLLabsTestEngine()
        elif name == "ct":
            from app.engines.ssl.certificate_transparency import CertificateTransparencyEngine
            _engines[name] = CertificateTransparencyEngine()
        elif name == "decoder":
            from app.engines.ssl.certificate_decoder import CertificateDecoderEngine
            _engines[name] = CertificateDecoderEngine()
        elif name == "chain":
            from app.engines.ssl.certificate_chain import CertificateChainEngine
            _engines[name] = CertificateChainEngine()
        elif name == "csr":
            from app.engines.ssl.csr_decoder import CSRDecoderEngine
            _engines[name] = CSRDecoderEngine()
        elif name == "tls_version":
            from app.engines.ssl.tls_version_check import TLSVersionCheckEngine
            _engines[name] = TLSVersionCheckEngine()
        elif name == "expiry":
            from app.engines.ssl.expiry_monitor import ExpiryMonitorEngine
            _engines[name] = ExpiryMonitorEngine()
    return _engines[name]

ssl_bp = Blueprint("ssl", __name__)

@ssl_bp.route("/certificate", methods=["POST"])
@timed_tool("ssl.certificate_checker")
def certificate_checker():
    target = get_target()
    options = get_options()
    return _get_engine("certificate_checker").check(target, port=options.get("port", 443)), target

@ssl_bp.route("/grade", methods=["POST"])
@timed_tool("ssl.grade")
def ssl_grade():
    target = get_target()
    options = get_options()
    return _get_engine("ssl_labs").grade(target, port=options.get("port", 443)), target

@ssl_bp.route("/ct", methods=["POST"])
@timed_tool("ssl.certificate_transparency")
def certificate_transparency():
    target = get_target()
    options = get_options()
    return _get_engine("ct").search(target, include_subdomains=options.get("include_subdomains", True)), target

@ssl_bp.route("/decode", methods=["POST"])
@timed_tool("ssl.certificate_decoder")
def certificate_decoder():
    target = get_target()
    return _get_engine("decoder").decode(target), target

@ssl_bp.route("/chain", methods=["POST"])
@timed_tool("ssl.certificate_chain")
def certificate_chain():
    target = get_target()
    options = get_options()
    return _get_engine("chain").validate(target, port=options.get("port", 443)), target

@ssl_bp.route("/csr", methods=["POST"])
@timed_tool("ssl.csr_decoder")
def csr_decoder():
    target = get_target()
    return _get_engine("csr").decode(target), target

@ssl_bp.route("/tls-versions", methods=["POST"])
@timed_tool("ssl.tls_version_check")
def tls_version_check():
    target = get_target()
    options = get_options()
    return _get_engine("tls_version").check(target, port=options.get("port", 443)), target

@ssl_bp.route("/expiry", methods=["POST"])
@timed_tool("ssl.expiry_monitor")
def expiry_monitor():
    target = get_target()
    options = get_options()
    return _get_engine("expiry").check(target, port=options.get("port", 443)), target
