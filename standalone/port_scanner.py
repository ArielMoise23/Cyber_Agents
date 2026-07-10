"""Standalone CLI: TCP port scan a domain, then ask a local Ollama model for a defensive testing strategy.

For a full multi-agent scan (recon, OSINT, admin panel discovery, IDOR heuristics, etc.),
use `python main.py <target>` instead. This script is kept for the original single-agent workflow.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.prompts import PromptTemplate

from agents.port_scan import DEFAULT_WEB_PORTS, parse_ports_arg, scan_ports
from core.llm import get_llm

STRATEGY_PROMPT = PromptTemplate(
    input_variables=["domain", "scan_result"],
    template=(
        "You are a defensive cybersecurity analyst.\n"
        "Given a port scan result for a domain, return safe next steps for security testing.\n\n"
        "Domain: {domain}\n\n"
        "Port scan output:\n{scan_result}\n\n"
        "Return:\n"
        "1) A brief scan report (2-4 sentences).\n"
        "2) Recommended next steps (5-10 bullet points) that are safe, defensive, and practical.\n"
        "Avoid offensive exploitation instructions."
    ),
)


def format_scan_result(open_ports: list[int], closed_ports: list[int]) -> str:
    lines = [f"Port {p} is open." for p in open_ports]
    lines += [f"Port {p} is closed or unreachable." for p in closed_ports]

    if open_ports:
        strategy = (
            f"Detected open ports: {', '.join(str(p) for p in open_ports)}.\n"
            "Next, consider banner grabbing, enumerating web/app endpoints on open ports, "
            "and reviewing TLS/certificate details for HTTPS ports."
        )
    else:
        strategy = (
            "No open common web ports detected. Consider footprinting other services, "
            "scanning a wider port range, and checking for firewall/WAF/CDN behavior."
        )

    return "\n".join(lines) + f"\n\nSuggested Security Testing Strategy:\n{strategy}"


def analyze_with_ollama(domain: str, ports: list[int] | None = None, llm=None) -> str:
    open_ports, closed_ports = scan_ports(domain, ports=ports)
    scan_result = format_scan_result(open_ports, closed_ports)

    llm = llm or get_llm()
    chain = STRATEGY_PROMPT | llm
    result = chain.invoke({"domain": domain, "scan_result": scan_result})
    return result.content


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python standalone/port_scanner.py <domain> [optional: comma-separated-ports]")
        print("Example: python standalone/port_scanner.py example.com")
        print("         python standalone/port_scanner.py example.com 80,443,8080")
        sys.exit(1)

    domain = sys.argv[1]
    ports: list[int] | None = None

    if len(sys.argv) >= 3:
        ports = parse_ports_arg(sys.argv[2])
        if not ports:
            print("Invalid port list provided. Must be comma-separated integers.")
            sys.exit(1)

    portlist_display = ports if ports is not None else DEFAULT_WEB_PORTS
    print(f"[1/2] Scanning ports for {domain} ({', '.join(str(p) for p in portlist_display)}) ...")
    print("[2/2] Sending scan results to Ollama for analysis ...")
    print(analyze_with_ollama(domain, ports=ports))
