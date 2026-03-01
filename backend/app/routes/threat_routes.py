"""
BoltEdge SecToolkit â€” Threat Intel Tool Routes
"""
from flask import Blueprint
from app.utils.formatters import timed_tool, get_target, get_options

_engines = {}

def _get_engine(name):
    if name not in _engines:
        from app.engines.threat.threat_engines import (
            IOCCheckerEngine, ReputationScorerEngine, CVELookupEngine,
            ExploitSearchEngine, ThreatFeedStatusEngine, STIXViewerEngine,
            AbuseContactFinderEngine)
        _map = {"ioc": IOCCheckerEngine, "reputation": ReputationScorerEngine,
                "cve": CVELookupEngine, "exploit": ExploitSearchEngine,
                "feed_status": ThreatFeedStatusEngine, "stix": STIXViewerEngine,
                "abuse": AbuseContactFinderEngine}
        if name in _map: _engines[name] = _map[name]()
    return _engines[name]

threat_bp = Blueprint("threat", __name__)

@threat_bp.route("/ioc", methods=["POST"])
@timed_tool("threat.ioc")
def ioc_check():
    target = get_target(); return _get_engine("ioc").check(target), target

@threat_bp.route("/reputation", methods=["POST"])
@timed_tool("threat.reputation")
def reputation_score():
    target = get_target(); return _get_engine("reputation").score(target), target

@threat_bp.route("/cve", methods=["POST"])
@timed_tool("threat.cve")
def cve_lookup():
    target = get_target(); return _get_engine("cve").lookup(target), target

@threat_bp.route("/exploit", methods=["POST"])
@timed_tool("threat.exploit")
def exploit_search():
    target = get_target(); return _get_engine("exploit").search(target), target

@threat_bp.route("/feeds", methods=["POST"])
@timed_tool("threat.feed_status")
def feed_status():
    return _get_engine("feed_status").status(), "feeds"

@threat_bp.route("/stix", methods=["POST"])
@timed_tool("threat.stix")
def stix_viewer():
    target = get_target(); return _get_engine("stix").parse(target), target

@threat_bp.route("/abuse", methods=["POST"])
@timed_tool("threat.abuse")
def abuse_contact():
    target = get_target(); return _get_engine("abuse").find(target), target
