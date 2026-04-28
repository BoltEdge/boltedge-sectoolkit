"""
SecToolkit 101 â€” Email Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        if name == "spf":
            from app.engines.email.spf_checker import SPFCheckerEngine; _engines[name] = SPFCheckerEngine()
        elif name == "dkim":
            from app.engines.email.dkim_validator import DKIMValidatorEngine; _engines[name] = DKIMValidatorEngine()
        elif name == "dmarc":
            from app.engines.email.dmarc_checker import DMARCCheckerEngine; _engines[name] = DMARCCheckerEngine()
        elif name == "mx_check":
            from app.engines.email.mx_check import MXCheckEngine; _engines[name] = MXCheckEngine()
        elif name == "email_validator":
            from app.engines.email.email_validator import EmailValidatorEngine; _engines[name] = EmailValidatorEngine()
        elif name == "spoofability":
            from app.engines.email.spoofability_test import SpoofabilityTestEngine; _engines[name] = SpoofabilityTestEngine()
        elif name == "header_analyser":
            from app.engines.email.header_analyser import HeaderAnalyserEngine; _engines[name] = HeaderAnalyserEngine()
        elif name == "bimi":
            from app.engines.email.bimi_checker import BIMICheckerEngine; _engines[name] = BIMICheckerEngine()
        elif name == "blacklist":
            from app.engines.email.email_blacklist_check import EmailBlacklistCheckEngine; _engines[name] = EmailBlacklistCheckEngine()
    return _engines[name]

email_bp = Blueprint("email", __name__)

@email_bp.route("/spf", methods=["POST"])
@timed_tool("email.spf")
def spf_checker():
    target = get_target(); return _get_engine("spf").check(target), target

@email_bp.route("/dkim", methods=["POST"])
@timed_tool("email.dkim")
def dkim_validator():
    target = get_target(); options = get_options()
    return _get_engine("dkim").check(target, selector=options.get("selector")), target

@email_bp.route("/dmarc", methods=["POST"])
@timed_tool("email.dmarc")
def dmarc_checker():
    target = get_target(); return _get_engine("dmarc").check(target), target

@email_bp.route("/mx-check", methods=["POST"])
@timed_tool("email.mx_check")
def mx_check():
    target = get_target(); return _get_engine("mx_check").check(target), target

@email_bp.route("/validate", methods=["POST"])
@timed_tool("email.validate")
def email_validate():
    target = get_target(); return _get_engine("email_validator").validate(target), target

@email_bp.route("/spoofability", methods=["POST"])
@timed_tool("email.spoofability")
def spoofability_test():
    target = get_target(); return _get_engine("spoofability").test(target), target

@email_bp.route("/headers", methods=["POST"])
@timed_tool("email.header_analyser")
def header_analyser():
    target = get_target(); return _get_engine("header_analyser").analyse(target), target

@email_bp.route("/bimi", methods=["POST"])
@timed_tool("email.bimi")
def bimi_checker():
    target = get_target(); options = get_options()
    return _get_engine("bimi").check(target, selector=options.get("selector", "default")), target

@email_bp.route("/blacklist", methods=["POST"])
@timed_tool("email.blacklist")
def email_blacklist():
    target = get_target(); return _get_engine("blacklist").check(target), target
