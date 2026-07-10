import argparse
from urllib.parse import urlparse

import requests
from langchain_core.prompts import PromptTemplate

from agents import (
    admin_panel,
    api_collector,
    auth_collector,
    debug_leak,
    headers_cors,
    idor,
    osint,
    port_scan,
    static_analysis,
)
from core import crawler, report
from core.http_client import get_session
from core.llm import get_llm
from core.models import ScanContext

PIPELINE = [
    osint.AGENT,
    port_scan.AGENT,
    headers_cors.AGENT,
    api_collector.AGENT,
    admin_panel.AGENT,
    auth_collector.AGENT,
    idor.AGENT,
    debug_leak.AGENT,
    static_analysis.AGENT,
]

SYNTHESIS_PROMPT = PromptTemplate(
    input_variables=["target", "findings_summary", "page_excerpt"],
    template=(
        "You are a defensive cybersecurity analyst producing an executive summary for a security scan.\n"
        "Target: {target}\n\n"
        "Structured findings from automated recon/analysis agents (severity, title, location):\n"
        "{findings_summary}\n\n"
        "Excerpt of the target's homepage content (for context only):\n"
        "{page_excerpt}\n\n"
        "Write a consolidated report with:\n"
        "1) A brief overall risk summary (3-5 sentences).\n"
        "2) The top findings ordered by severity, with a one-line 'why it matters' each.\n"
        "3) Recommended next steps for remediation/manual verification (5-10 bullet points).\n"
        "Stay strictly defensive/remediation-focused — do not provide exploitation instructions."
    ),
)


def normalize_target(raw_target: str) -> tuple[str, str]:
    """Return (base_url, domain), trying https:// then falling back to http://."""
    candidate = raw_target if "://" in raw_target else f"https://{raw_target}"
    domain = urlparse(candidate).netloc

    try:
        requests.get(candidate, timeout=5)
        return candidate.rstrip("/"), domain
    except requests.RequestException:
        pass

    http_candidate = f"http://{domain}"
    try:
        requests.get(http_candidate, timeout=5)
        return http_candidate, domain
    except requests.RequestException:
        return candidate.rstrip("/"), domain


def build_findings_summary(ctx: ScanContext) -> str:
    lines = []
    for result in ctx.results.values():
        for finding in result.findings:
            lines.append(f"- [{finding.severity}] ({result.agent_name}) {finding.title} — {finding.location or ''}")
        for error in result.errors:
            lines.append(f"- [error] ({result.agent_name}) {error}")
    return "\n".join(lines) if lines else "No findings recorded."


def run_synthesis(ctx: ScanContext, model: str) -> str | None:
    try:
        llm = get_llm(model=model)
        page_excerpt = ctx.results.get("static_analysis")
        excerpt_text = ""
        if page_excerpt:
            excerpt_text = str(page_excerpt.raw_data.get("page_content", ""))[:2000]

        chain = SYNTHESIS_PROMPT | llm
        result = chain.invoke({
            "target": ctx.target,
            "findings_summary": build_findings_summary(ctx),
            "page_excerpt": excerpt_text,
        })
        return result.content
    except Exception as exc:  # noqa: BLE001 - Ollama may be unreachable; report should still be written
        print(f"[!] LLM synthesis unavailable: {exc}")
        return None


def run_pipeline(target: str, model: str, max_pages: int, out_dir: str, skip: set[str], no_active_idor: bool) -> ScanContext:
    base_url, domain = normalize_target(target)
    ctx = ScanContext(target=base_url, domain=domain, session=get_session())
    ctx.options["skip_active_idor"] = no_active_idor

    for index, agent in enumerate(PIPELINE, start=1):
        if agent.name in skip:
            print(f"[{index}/{len(PIPELINE)}] Skipping {agent.display_name} (--skip)")
            continue

        print(f"[{index}/{len(PIPELINE)}] Running {agent.display_name} ...")
        ctx.results[agent.name] = agent.run(ctx)

        if agent.name == "osint":
            print("       Crawling discovered pages ...")
            crawler.crawl(ctx, max_pages=max_pages)

    print("[*] Synthesizing final report with Ollama ...")
    synthesis = run_synthesis(ctx, model)

    json_path = report.save_json(ctx, synthesis, out_dir=out_dir)
    md_path = report.save_markdown(ctx, synthesis, out_dir=out_dir)
    report.print_console_summary(ctx)
    print(f"[✔] Reports written to {json_path} and {md_path}")

    return ctx


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the full Cyber Agents security scanning pipeline against a target."
    )
    parser.add_argument("target", help="Domain or URL to scan, e.g. example.com or https://example.com")
    parser.add_argument("--model", default="llama3", help="Ollama model to use for report synthesis")
    parser.add_argument("--out-dir", default="reports", help="Directory to write JSON/Markdown reports to")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl for discovery")
    parser.add_argument("--skip", default="", help="Comma-separated agent names to skip, e.g. idor,admin_panel")
    parser.add_argument(
        "--no-active-idor",
        action="store_true",
        help="Disable IDOR agent's active adjacent-ID probing; only report pattern-based candidates",
    )
    args = parser.parse_args()

    skip = {name.strip() for name in args.skip.split(",") if name.strip()}
    run_pipeline(args.target, args.model, args.max_pages, args.out_dir, skip, args.no_active_idor)


if __name__ == "__main__":
    main()
