"""
BoltEdge SecToolkit — Response Formatters

Standard response format:
  Success: { success: true, tool: "ip.geolocation", target: "8.8.8.8", timestamp: "...", duration_ms: 12, result: { ... } }
  Error:   { success: false, tool: "ip.geolocation", target: "8.8.8.8", error: { code: "...", message: "..." } }
"""
import time
from datetime import datetime, timezone
from functools import wraps
from flask import jsonify, request
from app.utils.exceptions import SecToolkitError


def success_response(result, tool=None, target=None, duration_ms=None):
    """Format a successful tool response."""
    response = {
        "success": True,
        "tool": tool,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_ms": duration_ms,
        "result": result,
    }
    return jsonify(response), 200


def error_response(error, tool=None, target=None):
    """Format an error response from a SecToolkitError."""
    if isinstance(error, SecToolkitError):
        response = {
            "success": False,
            "tool": tool,
            "target": target,
            "error": error.to_dict(),
        }
        return jsonify(response), error.status_code

    # Fallback for unexpected errors
    response = {
        "success": False,
        "tool": tool,
        "target": target,
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
        },
    }
    return jsonify(response), 500


def register_error_handlers(app):
    """Register global error handlers on the Flask app."""

    @app.errorhandler(SecToolkitError)
    def handle_sectoolkit_error(error):
        tool = getattr(error, "tool", None)
        target = getattr(error, "target", None)
        return error_response(error, tool=tool, target=target)

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({
            "success": False,
            "error": {
                "code": "NOT_FOUND",
                "message": "The requested endpoint does not exist",
            },
        }), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return jsonify({
            "success": False,
            "error": {
                "code": "METHOD_NOT_ALLOWED",
                "message": f"Method {request.method} is not allowed for this endpoint",
            },
        }), 405

    @app.errorhandler(429)
    def handle_rate_limit(error):
        return jsonify({
            "success": False,
            "error": {
                "code": "RATE_LIMITED",
                "message": "Rate limit exceeded. Please slow down.",
            },
        }), 429

    @app.errorhandler(500)
    def handle_internal_error(error):
        return jsonify({
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
            },
        }), 500


def timed_tool(tool_name):
    """Decorator that wraps a route handler with timing and standard response format.

    Usage:
        @bp.route("/geolocation", methods=["POST"])
        @timed_tool("ip.geolocation")
        def geolocation():
            target = get_target()          # raises MissingInputError if absent
            result = engine.lookup(target)  # raises EngineError on failure
            return result, target           # return (result_dict, target_string)
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                result, target = f(*args, **kwargs)
                duration_ms = round((time.perf_counter() - start) * 1000)
                return success_response(
                    result=result,
                    tool=tool_name,
                    target=target,
                    duration_ms=duration_ms,
                )
            except SecToolkitError as e:
                return error_response(e, tool=tool_name)
            except Exception:
                return error_response(
                    SecToolkitError("An unexpected error occurred"),
                    tool=tool_name,
                )
        return wrapper
    return decorator


def get_target(field="target"):
    """Extract target from JSON body or query params. Raises MissingInputError if absent."""
    from app.utils.exceptions import MissingInputError

    data = request.get_json(silent=True) or {}
    target = data.get(field) or request.args.get(field, "").strip()

    if not target:
        raise MissingInputError(field)

    return target


def get_options():
    """Extract optional parameters from JSON body."""
    data = request.get_json(silent=True) or {}
    return data.get("options", {})