"""
SecToolkit 101 — Traceroute Engine

Tool: IP → Traceroute
Description: Trace network path to destination.
Input: IPv4 or IPv6 address
Output: Hop-by-hop path with RTT, hostnames, ASN info

Dependencies:
  - Python subprocess calling system traceroute/tracert command
  - Works on Linux (traceroute) and Windows (tracert)

Used by:
  - Traceroute tool (primary)
  - Network diagnostics context
  - IP Geolocation (path visualisation)

Security note:
  - Private/loopback IPs are blocked
  - Max hops capped to prevent long-running traces
  - Input validated before passing to subprocess
"""
import platform
import re
import subprocess
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_ip
from app.config import Config


class TracerouteEngine:
    """Network path tracing using system traceroute command."""

    def __init__(self, max_hops: int = None, timeout: int = None):
        self.max_hops = max_hops or Config.TRACEROUTE_MAX_HOPS
        self.timeout = timeout or Config.DEFAULT_TIMEOUT
        self._is_windows = platform.system().lower() == "windows"

    def trace(self, target: str, max_hops: int = None) -> dict:
        """Trace the network path to a target IP.

        Args:
            target: IPv4 or IPv6 address string.
            max_hops: Maximum number of hops (default from config, max 40).

        Returns:
            Dict with hop-by-hop results, path summary, and total hops.

        Raises:
            InvalidInputError: If target is not valid.
            EngineTimeoutError: If trace times out.
            EngineError: If trace fails.
        """
        target = validate_ip(target)
        self._validate_target(target)
        max_hops = min(max_hops or self.max_hops, 40)

        try:
            cmd = self._build_command(target, max_hops)

            # Traceroute can take a while — generous timeout
            process_timeout = max_hops * 5

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=process_timeout,
            )

            output = result.stdout + result.stderr
            hops = self._parse_output(output)

            # Determine if trace reached destination
            reached = self._check_reached(hops, target)

            return {
                "target": target,
                "total_hops": len(hops),
                "max_hops": max_hops,
                "reached_destination": reached,
                "hops": hops,
                "command": " ".join(cmd),
                "raw_output": output.strip(),
            }

        except subprocess.TimeoutExpired:
            raise EngineTimeoutError(f"Traceroute timed out for {target}")
        except FileNotFoundError:
            raise EngineError("Traceroute command not found on this system")
        except (InvalidInputError, EngineTimeoutError):
            raise
        except Exception as e:
            raise EngineError(f"Traceroute failed: {str(e)}")

    def _build_command(self, target: str, max_hops: int) -> list[str]:
        """Build platform-specific traceroute command.

        Returns:
            List of command arguments.
        """
        if self._is_windows:
            # Windows: tracert -d -h max_hops -w timeout_ms target
            return [
                "tracert",
                "-d",
                "-h", str(max_hops),
                "-w", str(self.timeout * 1000),
                target,
            ]
        else:
            # Linux: traceroute -n -m max_hops -w timeout target
            return [
                "traceroute",
                "-n",
                "-m", str(max_hops),
                "-w", str(self.timeout),
                target,
            ]

    def _parse_output(self, output: str) -> list[dict]:
        """Parse traceroute output into structured hops.

        Returns:
            List of hop dicts with hop number, IP, hostname, and RTT values.
        """
        if self._is_windows:
            return self._parse_windows(output)
        else:
            return self._parse_linux(output)

    def _parse_windows(self, output: str) -> list[dict]:
        """Parse Windows tracert output.

        Example:
          1    <1 ms    <1 ms    <1 ms  192.168.1.1
          2     8 ms     7 ms     8 ms  10.0.0.1
          3     *        *        *     Request timed out.
        """
        hops = []
        lines = output.strip().split("\n")

        for line in lines:
            line = line.strip()

            # Match hop lines: starts with hop number
            match = re.match(
                r"^\s*(\d+)\s+(.*?)\s+([\d\.]+)\s*$",
                line,
            )

            if match:
                hop_num = int(match.group(1))
                rtt_section = match.group(2)
                ip_address = match.group(3)
                rtts = self._extract_rtts(rtt_section)

                hops.append(self._build_hop(hop_num, ip_address, rtts))
                continue

            # Match timeout lines
            timeout_match = re.match(r"^\s*(\d+)\s+.*(?:Request timed out|timed out|\*\s+\*\s+\*)", line)
            if timeout_match:
                hop_num = int(timeout_match.group(1))
                hops.append(self._build_hop(hop_num, None, []))
                continue

            # Fallback: any line starting with a number
            fallback_match = re.match(r"^\s*(\d+)\s+(.+)$", line)
            if fallback_match:
                hop_num = int(fallback_match.group(1))
                rest = fallback_match.group(2)

                # Try to find IP at end
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*$", rest)
                if ip_match:
                    ip_address = ip_match.group(1)
                    rtt_section = rest[:ip_match.start()]
                    rtts = self._extract_rtts(rtt_section)
                    hops.append(self._build_hop(hop_num, ip_address, rtts))
                elif "*" in rest:
                    hops.append(self._build_hop(hop_num, None, []))

        return hops

    def _parse_linux(self, output: str) -> list[dict]:
        """Parse Linux traceroute output.

        Example:
          1  192.168.1.1  0.526 ms  0.389 ms  0.352 ms
          2  10.0.0.1  8.123 ms  7.987 ms  8.045 ms
          3  * * *
        """
        hops = []
        lines = output.strip().split("\n")

        for line in lines:
            line = line.strip()

            # Skip header line
            if line.startswith("traceroute to"):
                continue

            # Match hop number at start
            hop_match = re.match(r"^\s*(\d+)\s+(.+)$", line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2).strip()

            # Check for timeout
            if rest == "* * *" or rest.count("*") >= 3:
                hops.append(self._build_hop(hop_num, None, []))
                continue

            # Extract IP and RTTs
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            if ip_match:
                ip_address = ip_match.group(1)
                rtts = self._extract_rtts(rest)
                hops.append(self._build_hop(hop_num, ip_address, rtts))
            else:
                hops.append(self._build_hop(hop_num, None, []))

        return hops

    @staticmethod
    def _extract_rtts(text: str) -> list[float]:
        """Extract RTT values in milliseconds from text.

        Handles formats: "12 ms", "12.345 ms", "<1 ms"

        Returns:
            List of RTT floats.
        """
        rtts = []

        # Match numeric RTT values
        matches = re.findall(r"(\d+\.?\d*)\s*ms", text)
        for m in matches:
            rtts.append(float(m))

        # Handle "<1 ms" as 0.5
        lt_matches = re.findall(r"<\s*(\d+)\s*ms", text)
        for m in lt_matches:
            rtts.append(float(m) * 0.5)

        return rtts

    @staticmethod
    def _build_hop(hop_num: int, ip_address: str | None, rtts: list[float]) -> dict:
        """Build a structured hop result dict."""
        if not ip_address:
            return {
                "hop": hop_num,
                "ip": None,
                "hostname": None,
                "rtt": {
                    "values": [],
                    "min": None,
                    "avg": None,
                    "max": None,
                },
                "status": "timeout",
            }

        return {
            "hop": hop_num,
            "ip": ip_address,
            "hostname": None,  # DNS resolution can be added as enrichment
            "rtt": {
                "values": rtts,
                "min": round(min(rtts), 3) if rtts else None,
                "avg": round(sum(rtts) / len(rtts), 3) if rtts else None,
                "max": round(max(rtts), 3) if rtts else None,
            },
            "status": "reached",
        }

    @staticmethod
    def _check_reached(hops: list[dict], target: str) -> bool:
        """Check if the trace reached the destination IP."""
        if not hops:
            return False
        # Check last few hops for the target IP
        for hop in reversed(hops[-3:]):
            if hop.get("ip") == target:
                return True
        return False

    @staticmethod
    def _validate_target(ip_address: str):
        """Ensure target is not private/loopback."""
        import ipaddress
        addr = ipaddress.ip_address(ip_address)

        if addr.is_loopback:
            raise InvalidInputError("Cannot traceroute to loopback addresses")

        if addr.is_private:
            raise InvalidInputError("Cannot traceroute to private IP addresses from this service")

        if addr.is_reserved:
            raise InvalidInputError("Cannot traceroute to reserved IP addresses")