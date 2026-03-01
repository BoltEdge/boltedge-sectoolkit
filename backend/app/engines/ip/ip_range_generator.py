"""
BoltEdge SecToolkit — IP Range Generator Engine

Tool: IP → IP Range Generator
Description: Generate IP address ranges from CIDR notation.
Input: CIDR notation, IP range (start-end), or start IP + count
Output: List of IP addresses, range summary

Dependencies:
  - Python stdlib ipaddress module (no external libs)

Used by:
  - IP Range Generator tool (primary)
  - Subnet Calculator (range preview)
  - Port Scanner (bulk target generation)

Note: This is a client-side capable tool — no network calls needed.
      Backend version exists for API access and bulk operations.
      Max output capped at 10,000 IPs to prevent abuse.
"""
import ipaddress
from app.utils.exceptions import InvalidInputError


MAX_IPS = 10000


class IPRangeGeneratorEngine:
    """Generate lists of IP addresses from various range formats."""

    def generate(self, target: str, limit: int = None) -> dict:
        """Generate IP addresses from a range specification.

        Accepts:
          - CIDR: "192.168.1.0/24"
          - Range: "192.168.1.1-192.168.1.50"
          - Start + count: "192.168.1.1+100"

        Args:
            target: Range specification string.
            limit: Max IPs to return (default MAX_IPS).

        Returns:
            Dict with IP list, count, and range details.

        Raises:
            InvalidInputError: If input cannot be parsed.
        """
        target = target.strip()
        limit = min(limit or MAX_IPS, MAX_IPS)

        if "/" in target and "-" not in target:
            return self._from_cidr(target, limit)
        elif "-" in target:
            return self._from_range(target, limit)
        elif "+" in target:
            return self._from_count(target, limit)
        else:
            raise InvalidInputError(
                "Expected CIDR (192.168.1.0/24), range (1.1.1.1-1.1.1.50), "
                f"or start+count (1.1.1.1+100): {target}"
            )

    def _from_cidr(self, target: str, limit: int) -> dict:
        """Generate IPs from CIDR notation."""
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise InvalidInputError(f"Not a valid CIDR notation: {target}")

        total = network.num_addresses

        if total > MAX_IPS:
            ips = [str(ip) for ip, _ in zip(network.hosts(), range(limit))]
            truncated = True
        else:
            ips = [str(ip) for ip in network.hosts()] if network.prefixlen < 31 else [str(ip) for ip in network]
            truncated = False

        return {
            "input": target,
            "format": "cidr",
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "first_ip": ips[0] if ips else None,
            "last_ip": ips[-1] if ips else None,
            "total_in_range": total,
            "returned_count": len(ips),
            "truncated": truncated,
            "max_limit": MAX_IPS,
            "ips": ips,
        }

    def _from_range(self, target: str, limit: int) -> dict:
        """Generate IPs from start-end range."""
        parts = target.split("-", 1)
        if len(parts) != 2:
            raise InvalidInputError(f"Invalid range format. Expected start-end: {target}")

        try:
            start = ipaddress.ip_address(parts[0].strip())
            end = ipaddress.ip_address(parts[1].strip())
        except ValueError as e:
            raise InvalidInputError(f"Invalid IP in range: {str(e)}")

        if start.version != end.version:
            raise InvalidInputError("Start and end IPs must be the same version (both IPv4 or both IPv6)")

        if int(start) > int(end):
            raise InvalidInputError(f"Start IP ({start}) must be less than or equal to end IP ({end})")

        total = int(end) - int(start) + 1

        if total > MAX_IPS:
            ips = [str(ipaddress.ip_address(int(start) + i)) for i in range(limit)]
            truncated = True
        else:
            ips = [str(ipaddress.ip_address(int(start) + i)) for i in range(total)]
            truncated = False

        return {
            "input": target,
            "format": "range",
            "network": None,
            "broadcast": None,
            "first_ip": str(start),
            "last_ip": str(end),
            "total_in_range": total,
            "returned_count": len(ips),
            "truncated": truncated,
            "max_limit": MAX_IPS,
            "ips": ips,
        }

    def _from_count(self, target: str, limit: int) -> dict:
        """Generate IPs from start IP + count."""
        parts = target.split("+", 1)
        if len(parts) != 2:
            raise InvalidInputError(f"Invalid format. Expected IP+count: {target}")

        try:
            start = ipaddress.ip_address(parts[0].strip())
        except ValueError:
            raise InvalidInputError(f"Not a valid start IP: {parts[0].strip()}")

        try:
            count = int(parts[1].strip())
        except ValueError:
            raise InvalidInputError(f"Not a valid count: {parts[1].strip()}")

        if count < 1:
            raise InvalidInputError("Count must be at least 1")

        total = count
        actual_count = min(count, limit)

        ips = [str(ipaddress.ip_address(int(start) + i)) for i in range(actual_count)]

        return {
            "input": target,
            "format": "count",
            "network": None,
            "broadcast": None,
            "first_ip": str(start),
            "last_ip": ips[-1] if ips else str(start),
            "total_in_range": total,
            "returned_count": len(ips),
            "truncated": total > limit,
            "max_limit": MAX_IPS,
            "ips": ips,
        }