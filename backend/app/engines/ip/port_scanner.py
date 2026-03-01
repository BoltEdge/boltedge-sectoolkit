"""
BoltEdge SecToolkit — Port Scanner Engine

Tool: IP → Port Scanner
Description: Scan common ports on target IP.
Input: IPv4 or IPv6 address, optional port range
Output: Open/closed/filtered ports, service names, scan summary

Dependencies:
  - Python stdlib socket, asyncio (no external libs for TCP connect scan)
  - Scapy (optional, for SYN scan — requires root/admin)

Used by:
  - Port Scanner tool (primary)
  - IP Reputation (open port context)
  - Network → Status Checker (port availability)

Security note:
  - Only TCP connect scan is used (no raw packets, no root required)
  - Rate limited and capped at MAX_PORTS to prevent abuse
  - Private/loopback IPs are blocked
"""
import asyncio
import socket
from app.config import Config
from app.utils.exceptions import EngineError, EngineTimeoutError, InvalidInputError
from app.utils.validators import validate_ip, validate_port_range


# Top 100 most common ports (Nmap default)
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 81, 88, 110, 111,
    113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 201, 264,
    389, 443, 445, 464, 465, 500, 514, 515, 530, 543, 544, 548, 554, 587,
    593, 625, 631, 636, 646, 691, 860, 873, 902, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1080, 1194, 1214, 1241, 1311, 1337, 1433,
    1434, 1512, 1521, 1589, 1701, 1723, 1812, 1813, 1900, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2100, 2222, 2375, 2376, 3128, 3268,
    3269, 3306, 3389, 3690, 4443, 4567, 4711, 4712, 4993, 5000, 5001,
    5004, 5005, 5050, 5060, 5061, 5222, 5223, 5269, 5280, 5432, 5433,
    5500, 5555, 5631, 5632, 5800, 5900, 5901, 5938, 5984, 5985, 5986,
    6000, 6001, 6379, 6443, 6588, 6665, 6666, 6667, 6668, 6669, 7001,
    7002, 7199, 8000, 8008, 8080, 8081, 8083, 8088, 8090, 8118, 8123,
    8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888,
    9000, 9043, 9060, 9080, 9090, 9091, 9100, 9200, 9443, 9999, 10000,
    10443, 11211, 27017, 27018, 28017, 50000, 50070, 61616,
]

# Well-known service names
_SERVICE_MAP = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 43: "whois", 53: "dns", 67: "dhcp-server", 68: "dhcp-client",
    69: "tftp", 79: "finger", 80: "http", 81: "http-alt", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp", 194: "irc",
    389: "ldap", 443: "https", 445: "microsoft-ds", 464: "kpasswd",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer",
    543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp", 587: "submission",
    593: "http-rpc-epmap", 636: "ldaps", 873: "rsync", 902: "vmware-auth",
    990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs-or-iis",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-udp",
    1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius",
    1813: "radius-acct", 1900: "upnp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl", 2095: "webmail",
    2096: "webmail-ssl", 2222: "ssh-alt", 2375: "docker",
    2376: "docker-ssl", 3128: "squid-proxy", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4443: "https-alt", 5000: "upnp",
    5060: "sip", 5061: "sip-tls", 5222: "xmpp", 5223: "xmpp-ssl",
    5432: "postgresql", 5500: "vnc-http", 5555: "adb",
    5631: "pcanywhere", 5800: "vnc-http", 5900: "vnc", 5901: "vnc-1",
    5938: "teamviewer", 5984: "couchdb", 5985: "winrm",
    5986: "winrm-ssl", 6000: "x11", 6379: "redis", 6443: "kubernetes",
    6667: "irc", 7001: "weblogic", 7199: "cassandra-jmx",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8088: "http-alt", 8118: "privoxy",
    8123: "home-assistant", 8443: "https-alt", 8500: "consul",
    8834: "nessus", 8880: "http-alt", 8888: "http-alt",
    9000: "php-fpm", 9090: "prometheus", 9100: "jetdirect",
    9200: "elasticsearch", 9443: "https-alt", 9999: "abyss",
    10000: "webmin", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 50000: "sap", 61616: "activemq",
}


class PortScannerEngine:
    """TCP connect port scanner."""

    def __init__(self, timeout: float = None, max_ports: int = None):
        self.timeout = timeout or Config.PORT_SCAN_TIMEOUT
        self.max_ports = max_ports or Config.MAX_PORTS

    def scan(self, ip_address: str, ports: str = None) -> dict:
        """Scan ports on a target IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.
            ports: Optional port specification (e.g. "80,443", "1-1024", "top100").
                   Defaults to top 100 common ports.

        Returns:
            Dict with open/closed ports, service names, and scan summary.

        Raises:
            InvalidInputError: If IP or ports are not valid.
            EngineError: If scan fails.
        """
        ip_address = validate_ip(ip_address)
        self._validate_target(ip_address)

        port_list = self._resolve_ports(ports)

        try:
            results = asyncio.run(self._scan_ports(ip_address, port_list))

            open_ports = [r for r in results if r["state"] == "open"]
            closed_ports = [r for r in results if r["state"] == "closed"]
            filtered_ports = [r for r in results if r["state"] == "filtered"]

            return {
                "ip": ip_address,
                "scan_type": "tcp_connect",
                "ports_scanned": len(port_list),
                "summary": {
                    "open": len(open_ports),
                    "closed": len(closed_ports),
                    "filtered": len(filtered_ports),
                },
                "open_ports": open_ports,
                "all_results": results,
            }

        except InvalidInputError:
            raise
        except Exception as e:
            raise EngineError(f"Port scan failed: {str(e)}")

    async def _scan_ports(self, ip_address: str, ports: list[int]) -> list[dict]:
        """Scan all ports concurrently with semaphore limiting.

        Returns:
            List of per-port result dicts.
        """
        semaphore = asyncio.Semaphore(100)  # Max 100 concurrent connections

        async def scan_with_semaphore(port):
            async with semaphore:
                return await self._scan_single_port(ip_address, port)

        tasks = [scan_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks)

        # Sort by port number
        return sorted(results, key=lambda r: r["port"])

    async def _scan_single_port(self, ip_address: str, port: int) -> dict:
        """Scan a single port using TCP connect.

        Returns:
            Dict with port, state, and service info.
        """
        service = _SERVICE_MAP.get(port, "unknown")

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_address, port),
                timeout=self.timeout,
            )
            writer.close()
            await writer.wait_closed()

            return {
                "port": port,
                "state": "open",
                "service": service,
                "protocol": "tcp",
            }

        except asyncio.TimeoutError:
            return {
                "port": port,
                "state": "filtered",
                "service": service,
                "protocol": "tcp",
            }

        except ConnectionRefusedError:
            return {
                "port": port,
                "state": "closed",
                "service": service,
                "protocol": "tcp",
            }

        except OSError:
            return {
                "port": port,
                "state": "filtered",
                "service": service,
                "protocol": "tcp",
            }

    def _resolve_ports(self, ports: str = None) -> list[int]:
        """Resolve port specification to a list of integers.

        Args:
            ports: Port spec string or None for top 100.

        Returns:
            Sorted list of port integers.
        """
        if not ports or ports.lower() in ("top100", "default", "common"):
            return TOP_100_PORTS[:self.max_ports]

        if ports.lower() == "top20":
            return TOP_100_PORTS[:20]

        if ports.lower() == "top50":
            return TOP_100_PORTS[:50]

        if ports.lower() == "all":
            raise InvalidInputError("Scanning all 65535 ports is not allowed. Use a specific range.")

        return validate_port_range(ports)

    @staticmethod
    def _validate_target(ip_address: str):
        """Ensure target is not private/loopback."""
        import ipaddress
        addr = ipaddress.ip_address(ip_address)

        if addr.is_loopback:
            raise InvalidInputError("Cannot scan loopback addresses")

        if addr.is_private:
            raise InvalidInputError("Cannot scan private IP addresses from this service")

        if addr.is_reserved:
            raise InvalidInputError("Cannot scan reserved IP addresses")