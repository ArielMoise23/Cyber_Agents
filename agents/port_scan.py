import concurrent.futures
import socket

from agents.base import BaseAgent
from core.models import AgentResult, Finding, ScanContext

DEFAULT_WEB_PORTS = [80, 443, 8080, 8000, 8443, 8888, 8081, 1080, 8880, 2052]


def check_port(domain: str, port: int, timeout: float = 2.0) -> tuple[int, bool, str]:
    """Single-port TCP connect check."""
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return (port, True, f"Port {port} is open.")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return (port, False, f"Port {port} is closed or unreachable.")


def scan_ports(domain: str, ports: list[int] | None = None) -> tuple[list[int], list[int]]:
    """Scan TCP ports on a domain using concurrent connect tests.

    Returns (open_ports, closed_ports).
    """
    if ports is None:
        ports = DEFAULT_WEB_PORTS

    open_ports: list[int] = []
    closed_ports: list[int] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, domain, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, _message = future.result()
            (open_ports if is_open else closed_ports).append(port)

    return sorted(open_ports), sorted(closed_ports)


def parse_ports_arg(raw: str) -> list[int]:
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            ports.append(int(part))
    return ports


class PortScanAgent(BaseAgent):
    name = "port_scan"
    display_name = "Port Scanner"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        ports = ctx.options.get("ports")
        open_ports, closed_ports = scan_ports(ctx.domain, ports=ports)
        result.raw_data = {"open_ports": open_ports, "closed_ports": closed_ports}

        for port in open_ports:
            result.findings.append(
                Finding(
                    severity="info",
                    title=f"Open port {port}",
                    description=f"TCP port {port} accepted a connection on {ctx.domain}.",
                    location=f"{ctx.domain}:{port}",
                )
            )

        if not open_ports:
            result.findings.append(
                Finding(
                    severity="info",
                    title="No common web ports open",
                    description="None of the scanned common web ports responded. Consider a wider port range.",
                    location=ctx.domain,
                )
            )


AGENT = PortScanAgent()
