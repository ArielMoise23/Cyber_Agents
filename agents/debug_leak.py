import re
import uuid

from agents.base import BaseAgent
from core.http_client import safe_get
from core.models import AgentResult, Finding, ScanContext

SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    ("high", "Django DEBUG page exposed", re.compile(r"You're seeing this error because you have DEBUG = True")),
    ("high", "Werkzeug/Flask debugger exposed", re.compile(r"Werkzeug Debugger")),
    ("medium", "PHP warning/notice disclosed", re.compile(r"Warning: .*? in .*? on line \d+")),
    ("high", "PHP fatal error disclosed", re.compile(r"Fatal error:")),
    ("high", "ASP.NET Yellow Screen of Death", re.compile(r"Server Error in '.*?' Application")),
    ("medium", "Python traceback disclosed", re.compile(r"Traceback \(most recent call last\)")),
    ("medium", "Java stack trace disclosed", re.compile(r"at [\w.$]+\(\w+\.java:\d+\)")),
    ("medium", "MySQL error disclosed", re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE)),
    ("medium", "Oracle DB error disclosed", re.compile(r"ORA-\d{5}")),
    ("medium", "Generic unhandled exception page", re.compile(r"Internal Server Error.{0,80}(stack|trace)", re.IGNORECASE | re.DOTALL)),
]

EVIDENCE_SNIPPET_LEN = 200


class DebugLeakAgent(BaseAgent):
    name = "debug_leak"
    display_name = "Verbose Logging / Debug Info Detection"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        probe_url = ctx.target.rstrip("/") + f"/__nonexistent_{uuid.uuid4().hex[:12]}__"
        safe_get(ctx, probe_url)

        seen_titles: set[tuple[str, str]] = set()
        for url, body in ctx.response_cache.items():
            self._scan_body(body, url, result, seen_titles)

    def _scan_body(self, body: str, url: str, result: AgentResult, seen_titles: set) -> None:
        for severity, title, pattern in SIGNATURES:
            key = (title, url)
            if key in seen_titles:
                continue
            match = pattern.search(body)
            if match:
                seen_titles.add(key)
                start = max(match.start() - 40, 0)
                snippet = body[start:start + EVIDENCE_SNIPPET_LEN]
                result.findings.append(
                    Finding(
                        severity=severity,
                        title=title,
                        description=f"A debug/error signature ('{title}') was found in the response body.",
                        location=url,
                        evidence=snippet.strip(),
                    )
                )


AGENT = DebugLeakAgent()
