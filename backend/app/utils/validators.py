"""
SecToolkit 101 — Input Validators

Validates and sanitises user input before passing to engines.
Each validator returns the cleaned value or raises InvalidInputError.
"""
import re
import ipaddress
from app.utils.exceptions import InvalidInputError


# ============================================================
# IP Addresses
# ============================================================

def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address. Returns cleaned string."""
    value = value.strip()
    try:
        addr = ipaddress.ip_address(value)
        return str(addr)
    except ValueError:
        raise InvalidInputError(f"Not a valid IP address: {value}")


def validate_ip_or_cidr(value: str) -> str:
    """Validate an IP address or CIDR notation (e.g. 192.168.1.0/24)."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        network = ipaddress.ip_network(value, strict=False)
        return str(network)
    except ValueError:
        raise InvalidInputError(f"Not a valid IP address or CIDR: {value}")


def validate_cidr(value: str) -> str:
    """Validate CIDR notation only."""
    value = value.strip()
    if "/" not in value:
        raise InvalidInputError(f"Not a valid CIDR notation (missing /prefix): {value}")
    try:
        network = ipaddress.ip_network(value, strict=False)
        return str(network)
    except ValueError:
        raise InvalidInputError(f"Not a valid CIDR notation: {value}")


# ============================================================
# Domains
# ============================================================

# RFC-compliant domain pattern
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def validate_domain(value: str) -> str:
    """Validate a domain name. Returns lowercase cleaned string."""
    value = value.strip().lower().rstrip(".")

    # Strip protocol if accidentally included
    if "://" in value:
        value = value.split("://", 1)[1]

    # Strip path/query
    value = value.split("/")[0]
    value = value.split("?")[0]
    value = value.split(":")[0]  # Strip port

    if not _DOMAIN_RE.match(value):
        raise InvalidInputError(f"Not a valid domain name: {value}")

    if len(value) > 253:
        raise InvalidInputError("Domain name exceeds maximum length of 253 characters")

    return value


# ============================================================
# URLs
# ============================================================

_URL_RE = re.compile(
    r"^https?://"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"(:\d{1,5})?"
    r"(/[^\s]*)?$"
)


def validate_url(value: str) -> str:
    """Validate a URL (http/https). Returns cleaned string."""
    value = value.strip()

    # Auto-add scheme if missing
    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    if not _URL_RE.match(value):
        raise InvalidInputError(f"Not a valid URL: {value}")

    if len(value) > 2048:
        raise InvalidInputError("URL exceeds maximum length of 2048 characters")

    return value


# ============================================================
# Email Addresses
# ============================================================

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


def validate_email(value: str) -> str:
    """Validate an email address. Returns lowercase cleaned string."""
    value = value.strip().lower()

    if not _EMAIL_RE.match(value):
        raise InvalidInputError(f"Not a valid email address: {value}")

    if len(value) > 254:
        raise InvalidInputError("Email address exceeds maximum length of 254 characters")

    return value


def validate_email_domain(value: str) -> str:
    """Validate a domain for email tools (accepts both full email and domain)."""
    value = value.strip().lower()

    # If it's a full email, extract the domain
    if "@" in value:
        value = value.split("@", 1)[1]

    return validate_domain(value)


# ============================================================
# Hashes
# ============================================================

_HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
}


def validate_hash(value: str) -> str:
    """Validate a hash string (MD5, SHA-1, SHA-256, SHA-512). Returns lowercase."""
    value = value.strip().lower()

    for pattern in _HASH_PATTERNS.values():
        if pattern.match(value):
            return value

    raise InvalidInputError(
        f"Not a valid hash. Expected MD5 (32), SHA-1 (40), SHA-256 (64), or SHA-512 (128) hex chars."
    )


def identify_hash_type(value: str) -> str:
    """Identify the type of hash based on length. Returns type string."""
    value = value.strip().lower()

    for hash_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(value):
            return hash_type

    return "unknown"


# ============================================================
# MAC Address
# ============================================================

_MAC_RE = re.compile(
    r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$"
    r"|^[0-9A-Fa-f]{12}$"
    r"|^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$"
)


def validate_mac(value: str) -> str:
    """Validate a MAC address. Returns normalised colon-separated uppercase."""
    value = value.strip()

    if not _MAC_RE.match(value):
        raise InvalidInputError(f"Not a valid MAC address: {value}")

    # Normalise to AA:BB:CC:DD:EE:FF
    clean = re.sub(r"[:\-.]", "", value).upper()
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


# ============================================================
# Port Numbers
# ============================================================

def validate_port(value) -> int:
    """Validate a single port number (1-65535)."""
    try:
        port = int(value)
    except (ValueError, TypeError):
        raise InvalidInputError(f"Not a valid port number: {value}")

    if not 1 <= port <= 65535:
        raise InvalidInputError(f"Port must be between 1 and 65535, got: {port}")

    return port


def validate_port_range(value: str) -> list[int]:
    """Validate a port range string (e.g. '80', '80,443', '1-1024'). Returns list of ports."""
    value = value.strip()
    ports = set()

    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start = validate_port(start.strip())
            end = validate_port(end.strip())
            if start > end:
                raise InvalidInputError(f"Invalid port range: {start}-{end}")
            if (end - start) > 10000:
                raise InvalidInputError("Port range too large (max 10,000 ports)")
            ports.update(range(start, end + 1))
        else:
            ports.add(validate_port(part))

    if len(ports) > 10000:
        raise InvalidInputError("Too many ports specified (max 10,000)")

    return sorted(ports)


# ============================================================
# CVE ID
# ============================================================

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def validate_cve(value: str) -> str:
    """Validate a CVE identifier (e.g. CVE-2024-12345). Returns uppercase."""
    value = value.strip().upper()

    if not _CVE_RE.match(value):
        raise InvalidInputError(f"Not a valid CVE ID (expected CVE-YYYY-NNNNN): {value}")

    return value


# ============================================================
# ASN
# ============================================================

_ASN_RE = re.compile(r"^(AS)?\d{1,10}$", re.IGNORECASE)


def validate_asn(value: str) -> str:
    """Validate an ASN (e.g. AS15169 or 15169). Returns with AS prefix."""
    value = value.strip().upper()

    if not _ASN_RE.match(value):
        raise InvalidInputError(f"Not a valid ASN: {value}")

    if not value.startswith("AS"):
        value = f"AS{value}"

    return value


# ============================================================
# Generic / Smart Input
# ============================================================

def detect_input_type(value: str) -> str:
    """Auto-detect the type of input. Returns one of:
    'ipv4', 'ipv6', 'cidr', 'domain', 'url', 'email', 'md5',
    'sha1', 'sha256', 'sha512', 'mac', 'cve', 'asn', 'unknown'
    """
    value = value.strip()

    if not value:
        return "unknown"

    # CVE
    if _CVE_RE.match(value):
        return "cve"

    # ASN
    if _ASN_RE.match(value):
        return "asn"

    # Email
    if _EMAIL_RE.match(value):
        return "email"

    # URL
    if value.startswith(("http://", "https://")):
        return "url"

    # CIDR
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        except ValueError:
            pass

    # IP address
    try:
        addr = ipaddress.ip_address(value)
        return "ipv6" if addr.version == 6 else "ipv4"
    except ValueError:
        pass

    # Hash
    hash_type = identify_hash_type(value)
    if hash_type != "unknown":
        return hash_type

    # MAC address
    if _MAC_RE.match(value):
        return "mac"

    # Domain (fallback)
    if _DOMAIN_RE.match(value.lower()):
        return "domain"

    return "unknown"


def validate_target(value: str, expected_type: str = None) -> str:
    """Validate a target based on expected type, or auto-detect."""
    value = value.strip()

    if not value:
        raise InvalidInputError("Target cannot be empty")

    if len(value) > 2048:
        raise InvalidInputError("Input exceeds maximum length of 2048 characters")

    validators = {
        "ip": validate_ip,
        "ipv4": validate_ip,
        "ipv6": validate_ip,
        "cidr": validate_cidr,
        "domain": validate_domain,
        "url": validate_url,
        "email": validate_email,
        "hash": validate_hash,
        "mac": validate_mac,
        "cve": validate_cve,
        "asn": validate_asn,
    }

    if expected_type and expected_type in validators:
        return validators[expected_type](value)

    return value