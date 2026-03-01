"""
BoltEdge SecToolkit — Ping Test Engine

Tool: IP → Ping Test
Description: Test network connectivity to IP address.
Input: IPv4 or IPv6 address, or hostname
Output: RTT min/avg/max, packet loss, reachability status

Dependencies:
  - Python subprocess calling system ping command
  - Works on Linux (production) and Windows (development)

Used by:
  - Ping Test tool (primary)
  - Network → Status Checker (availability check)
  - Port Scanner (pre-scan reachability)

Security note:
  - Private/loopback IPs are blocked
  - Ping count and timeout are capped
  - Input is validated before passing to subprocess
"""
import asyncio
import platform
import re
import subprocess
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_ip
from app.config import Config


class PingTestEngine:
    """ICMP ping test using system ping command."""

    def __init__(self, count: int = None, timeout: int = None):
        self.count = count or Config.PING_COUNT
        self.timeout = timeout or Config.DEFAULT_TIMEOUT
        self._is_windows = platform.system().lower() == "windows"

    def ping(self, target: str, count: int = None) -> dict:
        """Ping a target IP address.

        Args:
            target: IPv4 or IPv6 address string.
            count: Number of ping packets (default from config, max 10).

        Returns:
            Dict with RTT stats, packet loss, and reachability.

        Raises:
            InvalidInputError: If target is not valid.
            EngineTimeoutError: If ping times out entirely.
            EngineError: If ping fails.
        """
        target = validate_ip(target)
        self._validate_target(target)
        count = min(count or self.count, 10)

        try:
            cmd = self._build_command(target, count)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + (count * 2),
            )

            output = result.stdout + result.stderr
            parsed = self._parse_output(output, target)
            parsed["command"] = " ".join(cmd)

            return parsed

        except subprocess.TimeoutExpired:
            raise EngineTimeoutError(f"Ping timed out for {target}")
        except FileNotFoundError:
            raise EngineError("Ping command not found on this system")
        except Exception as e:
            raise EngineError(f"Ping failed: {str(e)}")

    def _build_command(self, target: str, count: int) -> list[str]:
        """Build the platform-specific ping command.

        Returns:
            List of command arguments.
        """
        if self._is_windows:
            # Windows: ping -n count -w timeout_ms target
            return [
                "ping",
                "-n", str(count),
                "-w", str(self.timeout * 1000),
                target,
            ]
        else:
            # Linux/macOS: ping -c count -W timeout target
            return [
                "ping",
                "-c", str(count),
                "-W", str(self.timeout),
                target,
            ]

    def _parse_output(self, output: str, target: str) -> dict:
        """Parse ping command output into structured result.

        Handles both Windows and Linux/macOS formats.

        Returns:
            Dict with RTT stats and packet loss.
        """
        if self._is_windows:
            return self._parse_windows(output, target)
        else:
            return self._parse_linux(output, target)

    def _parse_windows(self, output: str, target: str) -> dict:
        """Parse Windows ping output.

        Example output:
            Pinging 8.8.8.8 with 32 bytes of data:
            Reply from 8.8.8.8: bytes=32 time=12ms TTL=117
            ...
            Ping statistics for 8.8.8.8:
                Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
            Approximate round trip times in milli-seconds:
                Minimum = 11ms, Maximum = 14ms, Average = 12ms
        """
        result = self._empty_result(target)

        # Parse individual replies for per-hop RTT
        replies = re.findall(r"time[=<](\d+)ms", output, re.IGNORECASE)
        if replies:
            rtts = [float(r) for r in replies]
            result["rtt"]["min"] = min(rtts)
            result["rtt"]["max"] = max(rtts)
            result["rtt"]["avg"] = round(sum(rtts) / len(rtts), 2)
            result["rtt"]["values"] = rtts

        # Parse packet stats
        loss_match = re.search(r"Lost\s*=\s*(\d+)\s*\((\d+)%", output)
        sent_match = re.search(r"Sent\s*=\s*(\d+)", output)
        recv_match = re.search(r"Received\s*=\s*(\d+)", output)

        if sent_match:
            result["packets"]["sent"] = int(sent_match.group(1))
        if recv_match:
            result["packets"]["received"] = int(recv_match.group(1))
        if loss_match:
            result["packets"]["lost"] = int(loss_match.group(1))
            result["packets"]["loss_percent"] = float(loss_match.group(2))

        # Parse TTL
        ttl_match = re.search(r"TTL[=](\d+)", output, re.IGNORECASE)
        if ttl_match:
            result["ttl"] = int(ttl_match.group(1))

        # Determine reachability
        result["is_alive"] = result["packets"]["received"] > 0
        result["raw_output"] = output.strip()

        return result

    def _parse_linux(self, output: str, target: str) -> dict:
        """Parse Linux/macOS ping output.

        Example output:
            PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
            64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=11.3 ms
            ...
            --- 8.8.8.8 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3004ms
            rtt min/avg/max/mdev = 11.234/12.456/14.123/1.023 ms
        """
        result = self._empty_result(target)

        # Parse individual replies
        replies = re.findall(r"time=(\d+\.?\d*)\s*ms", output)
        if replies:
            rtts = [float(r) for r in replies]
            result["rtt"]["values"] = rtts

        # Parse summary RTT line
        rtt_match = re.search(
            r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*"
            r"(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)",
            output,
        )
        if rtt_match:
            result["rtt"]["min"] = float(rtt_match.group(1))
            result["rtt"]["avg"] = float(rtt_match.group(2))
            result["rtt"]["max"] = float(rtt_match.group(3))
            result["rtt"]["mdev"] = float(rtt_match.group(4))

        # Parse packet stats
        pkt_match = re.search(
            r"(\d+)\s+packets?\s+transmitted.*?(\d+)\s+received.*?(\d+\.?\d*)%\s+(?:packet\s+)?loss",
            output,
            re.DOTALL,
        )
        if pkt_match:
            result["packets"]["sent"] = int(pkt_match.group(1))
            result["packets"]["received"] = int(pkt_match.group(2))
            result["packets"]["loss_percent"] = float(pkt_match.group(3))
            result["packets"]["lost"] = result["packets"]["sent"] - result["packets"]["received"]

        # Parse TTL
        ttl_match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if ttl_match:
            result["ttl"] = int(ttl_match.group(1))

        # Determine reachability
        result["is_alive"] = result["packets"]["received"] > 0
        result["raw_output"] = output.strip()

        return result

    @staticmethod
    def _empty_result(target: str) -> dict:
        """Return empty result template."""
        return {
            "ip": target,
            "is_alive": False,
            "ttl": None,
            "packets": {
                "sent": 0,
                "received": 0,
                "lost": 0,
                "loss_percent": 100.0,
            },
            "rtt": {
                "min": None,
                "avg": None,
                "max": None,
                "mdev": None,
                "values": [],
            },
            "raw_output": "",
            "command": "",
        }

    @staticmethod
    def _validate_target(ip_address: str):
        """Ensure target is not private/loopback."""
        import ipaddress
        addr = ipaddress.ip_address(ip_address)

        if addr.is_loopback:
            raise InvalidInputError("Cannot ping loopback addresses")

        if addr.is_private:
            raise InvalidInputError("Cannot ping private IP addresses from this service")

        if addr.is_reserved:
            raise InvalidInputError("Cannot ping reserved IP addresses")