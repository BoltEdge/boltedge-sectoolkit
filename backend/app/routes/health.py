"""
SecToolkit 101 — Health Check Route
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/api/health", methods=["GET"])
def health_check():
    """Basic health check — confirms the API is running."""
    return jsonify({
        "status": "healthy",
        "service": "sectoolkit-api",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200