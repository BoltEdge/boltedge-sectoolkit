"""
SecToolkit 101 — CIDR Calculator Engine

Tool: IP → CIDR Calculator
Description: Convert between CIDR and subnet masks.
Input: CIDR notation, subnet mask, or prefix length
Output: All equivalent representations, subnet table

Dependencies:
  - Python stdlib ipaddress module (no external libs)

Used by:
  - CIDR Calculator tool (primary)
  - Subnet Calculator (shared logic)
  - IP Range Generator (CIDR context)

Note: This is a client-side capable tool — no network calls needed.
      Backend version exists for API access and bulk operations.
"""
import ipaddress
from app.utils.exceptions import InvalidInputError


# Full IPv4 subnet reference table
_SUBNET_TABLE = [
    {"prefix": i, "mask": str(ipaddress.IPv4Network(f"0.0.0.0/{i}", strict=False).netmask),
     "wildcard": str(ipaddress.IPv4Address(int(ipaddress.IPv4Network(f"0.0.0.0/{i}", strict=False).netmask) ^ 0xFFFFFFFF)),
     "total_addresses": 2 ** (32 - i), "usable_hosts": max(2 ** (32 - i) - 2, 0) if i < 31 else 2 ** (32 - i)}
    for i in range(0, 33)
]


class CIDRCalculatorEngine:
    """Convert between CIDR notation, subnet masks, and prefix lengths."""

    def convert(self, target: str) -> dict:
        """Convert any subnet representation to all equivalent formats.

        Accepts:
          - CIDR: "192.168.1.0/24"
          - Subnet mask: "255.255.255.0"
          - Prefix length: "/24" or "24"
          - IP + mask: "192.168.1.0 255.255.255.0"

        Args:
            target: Any subnet representation.

        Returns:
            Dict with all equivalent formats and details.

        Raises:
            InvalidInputError: If input cannot be parsed.
        """
        target = target.strip()

        prefix = self._parse_to_prefix(target)
        network = ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False)

        netmask = str(network.netmask)
        netmask_int = int(network.netmask)
        wildcard_int = netmask_int ^ 0xFFFFFFFF
        wildcard = str(ipaddress.IPv4Address(wildcard_int))
        total = 2 ** (32 - prefix)
        usable = max(total - 2, 0) if prefix < 31 else total

        # Binary
        netmask_bin = ".".join(f"{int(o):08b}" for o in netmask.split("."))

        return {
            "input": target,
            "prefix_length": prefix,
            "cidr_notation": f"/{prefix}",
            "subnet_mask": netmask,
            "wildcard_mask": wildcard,
            "total_addresses": total,
            "usable_hosts": usable,
            "binary_mask": netmask_bin,
            "hex_mask": f"0x{netmask_int:08X}",
            "ip_class_default": self._default_class_for_prefix(prefix),
        }

    def subnet_table(self) -> list[dict]:
        """Return the full /0 to /32 subnet reference table.

        Returns:
            List of dicts with prefix, mask, wildcard, total_addresses, usable_hosts.
        """
        return _SUBNET_TABLE

    def compare(self, cidr_a: str, cidr_b: str) -> dict:
        """Compare two CIDR ranges — check overlap, containment, etc.

        Args:
            cidr_a: First CIDR notation (e.g. "10.0.0.0/8").
            cidr_b: Second CIDR notation (e.g. "10.1.0.0/16").

        Returns:
            Dict with comparison results.

        Raises:
            InvalidInputError: If either input is not valid CIDR.
        """
        try:
            net_a = ipaddress.ip_network(cidr_a.strip(), strict=False)
            net_b = ipaddress.ip_network(cidr_b.strip(), strict=False)
        except ValueError as e:
            raise InvalidInputError(f"Invalid CIDR notation: {str(e)}")

        overlaps = net_a.overlaps(net_b)
        a_contains_b = net_b.subnet_of(net_a) if hasattr(net_b, 'subnet_of') else False
        b_contains_a = net_a.subnet_of(net_b) if hasattr(net_a, 'subnet_of') else False

        return {
            "network_a": str(net_a),
            "network_b": str(net_b),
            "overlaps": overlaps,
            "a_contains_b": a_contains_b,
            "b_contains_a": b_contains_a,
            "relationship": self._describe_relationship(overlaps, a_contains_b, b_contains_a),
            "details_a": {
                "total_addresses": net_a.num_addresses,
                "prefix_length": net_a.prefixlen,
            },
            "details_b": {
                "total_addresses": net_b.num_addresses,
                "prefix_length": net_b.prefixlen,
            },
        }

    def _parse_to_prefix(self, target: str) -> int:
        """Parse any input format into a prefix length integer.

        Raises:
            InvalidInputError: If input cannot be parsed.
        """
        # Pure prefix: "/24" or "24"
        clean = target.lstrip("/")
        if clean.isdigit():
            prefix = int(clean)
            if 0 <= prefix <= 32:
                return prefix
            raise InvalidInputError(f"Prefix length must be 0-32, got: {prefix}")

        # Subnet mask: "255.255.255.0"
        if self._is_dotted_mask(target):
            return self._mask_to_prefix(target)

        # CIDR: "192.168.1.0/24"
        if "/" in target:
            parts = target.split("/", 1)
            suffix = parts[1].strip()

            # Dotted mask after slash: "192.168.1.0/255.255.255.0"
            if self._is_dotted_mask(suffix):
                return self._mask_to_prefix(suffix)

            # Numeric prefix after slash
            if suffix.isdigit():
                prefix = int(suffix)
                if 0 <= prefix <= 32:
                    return prefix

        # Space-separated: "192.168.1.0 255.255.255.0"
        parts = target.split()
        if len(parts) == 2 and self._is_dotted_mask(parts[1]):
            return self._mask_to_prefix(parts[1])

        raise InvalidInputError(
            f"Cannot parse subnet input. Expected CIDR (/24), mask (255.255.255.0), or prefix (24): {target}"
        )

    def _mask_to_prefix(self, mask: str) -> int:
        """Convert dotted subnet mask to prefix length.

        Raises:
            InvalidInputError: If mask is not valid.
        """
        try:
            mask_int = int(ipaddress.IPv4Address(mask.strip()))
        except ValueError:
            raise InvalidInputError(f"Not a valid subnet mask: {mask}")

        # Verify it's a valid mask (contiguous 1s followed by 0s)
        binary = f"{mask_int:032b}"
        if "01" in binary.replace("0", "", binary.index("0") if "0" in binary else 32):
            # More robust check
            try:
                ipaddress.IPv4Network(f"0.0.0.0/{mask.strip()}", strict=False)
            except ValueError:
                raise InvalidInputError(f"Not a valid subnet mask (non-contiguous bits): {mask}")

        return bin(mask_int).count("1")

    @staticmethod
    def _is_dotted_mask(value: str) -> bool:
        """Check if value looks like a dotted subnet mask."""
        parts = value.strip().split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def _default_class_for_prefix(prefix: int) -> str:
        """Return the classful default for context."""
        if prefix <= 8:
            return "Class A (/8)"
        elif prefix <= 16:
            return "Class B (/16)"
        elif prefix <= 24:
            return "Class C (/24)"
        else:
            return "Classless (VLSM)"

    @staticmethod
    def _describe_relationship(overlaps: bool, a_contains_b: bool, b_contains_a: bool) -> str:
        """Describe the relationship between two networks."""
        if a_contains_b and b_contains_a:
            return "identical"
        if a_contains_b:
            return "A contains B (B is a subnet of A)"
        if b_contains_a:
            return "B contains A (A is a subnet of B)"
        if overlaps:
            return "partial overlap"
        return "no overlap (disjoint)"