import re

import requests

from agents.base import BaseAgent
from core.models import AgentResult, Finding, ScanContext

PAGE_CONTENT_TRUNCATE = 8000
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
EXTERNAL_SCRIPT_SRC_RE = re.compile(r"<script[^>]*\bsrc=[\"']([^\"']+)[\"']", re.IGNORECASE)


def fetch_page_content(url: str) -> str:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:  # noqa: BLE001 - surfaced as an error string for callers
        return f"Error fetching URL content: {e}"


class StaticAnalysisAgent(BaseAgent):
    name = "static_analysis"
    display_name = "Static Page Analysis"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        content = ctx.response_cache.get(ctx.target)
        if content is None:
            content = fetch_page_content(ctx.target)

        if content.startswith("Error fetching URL content:"):
            result.errors.append(content)
            return

        result.raw_data = {"page_content": content[:PAGE_CONTENT_TRUNCATE]}

        inline_script_count = len(INLINE_SCRIPT_RE.findall(content))
        if inline_script_count:
            result.findings.append(
                Finding(
                    severity="info",
                    title=f"{inline_script_count} inline <script> block(s) found",
                    description="Inline scripts increase XSS blast radius and complicate a strict CSP.",
                    location=ctx.target,
                )
            )

        external_domains = set()
        for src in EXTERNAL_SCRIPT_SRC_RE.findall(content):
            if src.startswith("http") and ctx.domain not in src:
                external_domains.add(src.split("/")[2])
        for ext_domain in external_domains:
            result.findings.append(
                Finding(
                    severity="info",
                    title="External script dependency",
                    description=f"Page loads a script from third-party domain {ext_domain}.",
                    location=ext_domain,
                )
            )


AGENT = StaticAnalysisAgent()
