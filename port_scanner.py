import concurrent.futures
import socket
import sys

from langchain_core.prompts import PromptTemplate
from langchain_community.chat_models import ChatOllama

# A compact “common web ports” set. You can override from CLI.
DEFAULT_WEB_PORTS = [80, 443, 8080, 8000, 8443, 8888, 8081, 1080, 8880, 2052]

# LangChain compatibility shim:
# Newer LangChain versions removed `langchain.agents.initialize_agent`.
# This script no longer relies on tool-calling agents, but some legacy code
# below still references `Tool`, `AgentType`, and `initialize_agent` at import time.
# Define minimal stubs so the module can import cleanly.
class Tool:  # pragma: no cover
    def __init__(self, name: str, description: str, func):
        self.name = name
        self.description = description
        self.func = func


class AgentType:  # pragma: no cover
    ZERO_SHOT_REACT_DESCRIPTION = "zero_shot_react_description"


def initialize_agent(tools, llm, agent, verbose=False, agent_kwargs=None):  # pragma: no cover
    class _StubAgent:
        def run(self, domain):
            # Fallback: call the first tool directly.
            return tools[0].func(domain)

    return _StubAgent()

def check_port(domain: str, port: int, timeout: float = 2.0) -> tuple[int, bool, str]:
    """Single-port TCP connect check."""
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return (port, True, f"Port {port} is open.")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return (port, False, f"Port {port} is closed or unreachable.")


def scan_ports(domain: str, ports: list[int] | None = None) -> str:
    """
    Scan TCP ports on a domain using concurrent connect tests.
    Returns a detailed multi-line string of open/closed results.
    """
    if ports is None:
        ports = DEFAULT_WEB_PORTS

    open_ports: list[int] = []
    results: list[tuple[int, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, domain, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, message = future.result()
            results.append((ports.index(port), message))  # preserve ordering
            if is_open:
                open_ports.append(port)

    results_sorted = [msg for _, msg in sorted(results)]
    out = "\n".join(results_sorted)

    if open_ports:
        open_list = ", ".join(str(p) for p in sorted(open_ports))
        strategy = (
            f"Detected open ports: {open_list}.\n"
            "Next, consider banner grabbing, enumerating web/app endpoints on open ports, "
            "and reviewing TLS/certificate details for HTTPS ports."
        )
    else:
        strategy = (
            "No open common web ports detected. Consider footprinting other services, "
            "scanning a wider port range, and checking for firewall/WAF/CDN behavior."
        )

    return f"{out}\n\nSuggested Security Testing Strategy:\n{strategy}"

def analyze_with_ollama(domain: str, llm: ChatOllama | None = None, ports: list[int] | None = None) -> str:
    """
    Scan ports on a domain, then ask the local Ollama model for defensive guidance.
    """
    scan_result = scan_ports(domain, ports=ports)

    if llm is None:
        llm = ChatOllama(model="llama3", temperature=0.2)

    prompt = PromptTemplate(
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

    chain = prompt | llm
    result = chain.invoke({"domain": domain, "scan_result": scan_result})
    return result.content


def parse_ports_arg(raw: str) -> list[int]:
    # Accept comma-separated ports, e.g. "80,443,8080"
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            ports.append(int(part))
    return ports

# Register the scanning function as a tool for agent use
port_scanner_tool = Tool(
    name="port_scanner",
    description="Scans ports 80 and 443 of a given domain to determine if they are open or closed, then suggests a security testing strategy. Use this to start web security assessments.",
    func=scan_ports
)

# Local LLM (Ollama) configuration
llm = ChatOllama(model="llama3", temperature=0.2)

# Prompt tells the agent how to reason from the scan to a security recommendation
prompt = PromptTemplate(
    input_variables=["input"],
    template=(
        "You are a cybersecurity analyst assistant. "
        "Given a domain, use the port_scanner tool to check open ports (80, 443), then — "
        "based on the scan outcome — suggest an initial web application security testing strategy. "
        "Domain to assess: {input}\n"
        "Output a brief scan report and your recommended next steps for security testing."
    )
)

# Combine the tool, LLM, and prompt into an agent
agent = initialize_agent(
    tools=[port_scanner_tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,  # This enables tool-use by the agent
    verbose=True,
    agent_kwargs={"prompt": prompt}
)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <domain> [optional: comma-separated-ports]")
        print("Example: python port_scanner.py example.com")
        print("         python port_scanner.py example.com 80,443,8080")
        sys.exit(1)
    else:
        domain = sys.argv[1]
        ports: list[int] | None = None

        if len(sys.argv) >= 3:
            ports = parse_ports_arg(sys.argv[2])
            if not ports:
                print("Invalid port list provided. Must be comma-separated integers.")
                sys.exit(1)

        portlist_display = ports if ports is not None else DEFAULT_WEB_PORTS
        print(f"[1/2] Scanning ports for {domain} ({', '.join(str(p) for p in portlist_display)}) ...")
        print(f"[2/2] Sending scan results to Ollama for analysis ...")
        print(analyze_with_ollama(domain, ports=ports))