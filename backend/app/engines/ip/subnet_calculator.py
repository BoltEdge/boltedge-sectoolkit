"""
BoltEdge SecToolkit — Subnet Calculator Engine

Tool: IP → Subnet Calculator
Description: Calculate IP subnets and network ranges.
Input: IP address with subnet mask or CIDR notation (e.g. 192.168.1.0/24)
Output: Network/broadcast address, usable range, host count, wildcard mask, binary

Dependencies:
  - Python stdlib ipaddress module (no external libs)

Used by:
  - Subnet Calculator tool (primary)
  - CIDR Calculator (shared logic)
  - IP Range Generator (range context)

Note: This is a client-side capable tool — no network calls needed.
      Backend version exists for API access and bulk operations.
"""
import ipaddress
from app.utils.exceptions import InvalidInputError


class SubnetCalculatorEngine:
    """Calculate subnet details from IP/CIDR input."""

    def calculate(self, target: str) -> dict:
        """Calculate full subnet details for an IP/CIDR input.

        Args:
            target: IP with CIDR (e.g. "192.168.1.0/24") or
                    IP with subnet mask (e.g. "192.168.1.0/255.255.255.0").

        Returns:
            Dict with network details, usable range, host count, etc.

        Raises:
            InvalidInputError: If input is not valid.
        """
        target = target.strip()

        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            # Try parsing as "IP MASK" format (space-separated)
            network = self._parse_ip_mask(target)

        if network.version == 4:
            return self._calculate_v4(network)
        else:
            return self._calculate_v6(network)

    def _calculate_v4(self, network: ipaddress.IPv4Network) -> dict:
        """Calculate details for an IPv4 network."""
        total_hosts = network.num_addresses
        usable_hosts = max(total_hosts - 2, 0) if network.prefixlen < 31 else total_hosts

        # Usable range
        hosts = list(network.hosts()) if network.prefixlen < 31 else list(network)
        first_usable = str(hosts[0]) if hosts else str(network.network_address)
        last_usable = str(hosts[-1]) if hosts else str(network.broadcast_address)

        # Wildcard mask (inverse of netmask)
        netmask_int = int(network.netmask)
        wildcard_int = netmask_int ^ 0xFFFFFFFF
        wildcard = str(ipaddress.IPv4Address(wildcard_int))

        # Binary representations
        network_bin = self._ip_to_binary_v4(network.network_address)
        netmask_bin = self._ip_to_binary_v4(network.netmask)

        return {
            "input": str(network),
            "version": 4,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "wildcard_mask": wildcard,
            "prefix_length": network.prefixlen,
            "cidr": str(network),
            "first_usable": first_usable,
            "last_usable": last_usable,
            "total_addresses": total_hosts,
            "usable_hosts": usable_hosts,
            "ip_class": self._get_ip_class(network.network_address),
            "is_private": network.is_private,
            "binary": {
                "network": network_bin,
                "netmask": netmask_bin,
            },
        }

    def _calculate_v6(self, network: ipaddress.IPv6Network) -> dict:
        """Calculate details for an IPv6 network."""
        total_hosts = network.num_addresses
        # IPv6 doesn't reserve network/broadcast in the same way
        usable_hosts = total_hosts

        return {
            "input": str(network),
            "version": 6,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "wildcard_mask": None,
            "prefix_length": network.prefixlen,
            "cidr": str(network),
            "first_usable": str(network.network_address),
            "last_usable": str(network.broadcast_address),
            "total_addresses": total_hosts,
            "usable_hosts": usable_hosts,
            "ip_class": None,
            "is_private": network.is_private,
            "binary": None,
        }

    def _parse_ip_mask(self, target: str) -> ipaddress.IPv4Network:
        """Parse 'IP MASK' or 'IP/MASK' formats.

        Handles:
          - "192.168.1.0 255.255.255.0"
          - "192.168.1.0/255.255.255.0"

        Returns:
            IPv4Network object.

        Raises:
            InvalidInputError: If format is not valid.
        """
        # Try space-separated
        parts = target.split()
        if len(parts) == 2:
            try:
                ip = parts[0]
                mask = parts[1]
                # Check if mask is dotted notation
                if "." in mask:
                    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    return network
            except ValueError:
                pass

        # Try slash with dotted mask
        if "/" in target:
            parts = target.split("/", 1)
            if "." in parts[1]:
                try:
                    return ipaddress.ip_network(target, strict=False)
                except ValueError:
                    pass

        raise InvalidInputError(
            f"Not a valid subnet. Expected CIDR (192.168.1.0/24) or IP+mask (192.168.1.0 255.255.255.0): {target}"
        )

    @staticmethod
    def _ip_to_binary_v4(addr: ipaddress.IPv4Address) -> str:
        """Convert IPv4 address to dotted binary string.

        Example: "11000000.10101000.00000001.00000000"
        """
        octets = str(addr).split(".")
        return ".".join(f"{int(o):08b}" for o in octets)

    @staticmethod
    def _get_ip_class(addr: ipaddress.IPv4Address) -> str:
        """Determine the classful IP class (A/B/C/D/E)."""
        first_octet = int(str(addr).split(".")[0])

        if first_octet < 128:
            return "A"
        elif first_octet < 192:
            return "B"
        elif first_octet < 224:
            return "C"
        elif first_octet < 240:
            return "D (multicast)"
        else:
            return "E (reserved)"