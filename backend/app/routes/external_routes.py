"""
BoltEdge SecToolkit - External API Routes

Provides:
    - GET /api/external/status - show which APIs are configured
    - POST /api/external/enrich/* - unified enrichment endpoints
"""
from flask import Blueprint, jsonify
from app.utils.formatters import timed_tool, get_target

external_bp = Blueprint("external", __name__)


@external_bp.route("/status", methods=["GET"])
def api_status():
    from app.services.api_clients import get_available_apis
    return jsonify({"success": True, "apis": get_available_apis()})


@external_bp.route("/enrich/ip", methods=["POST"])
@timed_tool("external.enrich_ip")
def enrich_ip():
    target = get_target()
    from app.services.enrichment import enrich_ip as _enrich
    return _enrich(target), target


@external_bp.route("/enrich/domain", methods=["POST"])
@timed_tool("external.enrich_domain")
def enrich_domain():
    target = get_target()
    from app.services.enrichment import enrich_domain as _enrich
    return _enrich(target), target


@external_bp.route("/enrich/hash", methods=["POST"])
@timed_tool("external.enrich_hash")
def enrich_hash():
    target = get_target()
    from app.services.enrichment import enrich_hash as _enrich
    return _enrich(target), target


@external_bp.route("/enrich/url", methods=["POST"])
@timed_tool("external.enrich_url")
def enrich_url():
    target = get_target()
    from app.services.enrichment import enrich_url as _enrich
    return _enrich(target), target


@external_bp.route("/enrich/cve", methods=["POST"])
@timed_tool("external.enrich_cve")
def enrich_cve():
    target = get_target()
    from app.services.enrichment import enrich_cve as _enrich
    return _enrich(target), target


@external_bp.route("/enrich/password", methods=["POST"])
@timed_tool("external.enrich_password")
def enrich_password():
    target = get_target()
    from app.services.enrichment import enrich_password as _enrich
    return _enrich(target), target