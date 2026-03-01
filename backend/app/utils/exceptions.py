"""
BoltEdge SecToolkit — Custom Exceptions
"""


class SecToolkitError(Exception):
    """Base exception for all SecToolkit errors."""

    def __init__(self, message="An error occurred", code="UNKNOWN_ERROR", status_code=500):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(self.message)

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
        }


# --- Input Errors (400) ---

class InvalidInputError(SecToolkitError):
    """Raised when user input fails validation."""

    def __init__(self, message="Invalid input provided"):
        super().__init__(message=message, code="INVALID_INPUT", status_code=400)


class MissingInputError(SecToolkitError):
    """Raised when a required field is missing."""

    def __init__(self, field="target"):
        super().__init__(
            message=f"Missing required field: {field}",
            code="MISSING_INPUT",
            status_code=400,
        )


# --- Auth Errors (401, 403) ---

class AuthenticationError(SecToolkitError):
    """Raised when authentication fails."""

    def __init__(self, message="Authentication required"):
        super().__init__(message=message, code="AUTH_REQUIRED", status_code=401)


class InvalidApiKeyError(SecToolkitError):
    """Raised when an API key is invalid or revoked."""

    def __init__(self, message="Invalid or revoked API key"):
        super().__init__(message=message, code="INVALID_API_KEY", status_code=401)


class ForbiddenError(SecToolkitError):
    """Raised when user lacks permission for the action."""

    def __init__(self, message="You do not have permission to perform this action"):
        super().__init__(message=message, code="FORBIDDEN", status_code=403)


class PlanRequiredError(SecToolkitError):
    """Raised when a feature requires a higher plan."""

    def __init__(self, required_plan="Pro"):
        super().__init__(
            message=f"This feature requires a {required_plan} plan",
            code="PLAN_REQUIRED",
            status_code=403,
        )


# --- Rate Limiting (429) ---

class RateLimitError(SecToolkitError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message="Rate limit exceeded. Please slow down."):
        super().__init__(message=message, code="RATE_LIMITED", status_code=429)


# --- Not Found (404) ---

class NotFoundError(SecToolkitError):
    """Raised when a resource is not found."""

    def __init__(self, message="Resource not found"):
        super().__init__(message=message, code="NOT_FOUND", status_code=404)


class ToolNotFoundError(SecToolkitError):
    """Raised when an invalid tool is requested."""

    def __init__(self, tool_name=""):
        super().__init__(
            message=f"Tool not found: {tool_name}",
            code="TOOL_NOT_FOUND",
            status_code=404,
        )


# --- Engine Errors (502, 504) ---

class EngineError(SecToolkitError):
    """Raised when an engine encounters a processing error."""

    def __init__(self, message="Tool processing error"):
        super().__init__(message=message, code="ENGINE_ERROR", status_code=500)


class EngineTimeoutError(SecToolkitError):
    """Raised when an engine operation times out."""

    def __init__(self, message="Operation timed out"):
        super().__init__(message=message, code="TIMEOUT", status_code=504)


class ExternalServiceError(SecToolkitError):
    """Raised when an external API call fails."""

    def __init__(self, service="", message="External service unavailable"):
        super().__init__(
            message=f"{service}: {message}" if service else message,
            code="EXTERNAL_SERVICE_ERROR",
            status_code=502,
        )


# --- Data Errors ---

class DatabaseNotFoundError(SecToolkitError):
    """Raised when a required data file is missing (e.g. GeoLite2 DB)."""

    def __init__(self, database=""):
        super().__init__(
            message=f"Required database not found: {database}",
            code="DATABASE_NOT_FOUND",
            status_code=500,
        )