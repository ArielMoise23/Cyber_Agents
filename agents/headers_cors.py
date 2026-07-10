from agents.base import BaseAgent
from core.http_client import safe_get
from core.models import AgentResult, Finding, ScanContext

MISSING_HEADER_CHECKS = [
    ("Content-Security-Policy", "low"),
    ("Strict-Transport-Security", "low"),
    ("X-Frame-Options", "low"),
    ("X-Content-Type-Options", "low"),
    ("Referrer-Policy", "low"),
    ("Permissions-Policy", "low"),
]

INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

PROBE_ORIGIN = "https://cors-probe.invalid"


class HeadersCorsAgent(BaseAgent):
    name = "headers_cors"
    display_name = "Headers & CORS Analysis"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        response = safe_get(ctx, ctx.target)
        if response is None:
            result.errors.append(f"Could not fetch {ctx.target}.")
            return

        for header_name, severity in MISSING_HEADER_CHECKS:
            if header_name not in response.headers:
                result.findings.append(
                    Finding(
                        severity=severity,
                        title=f"Missing {header_name} header",
                        description=f"The response did not include a {header_name} header.",
                        location=ctx.target,
                    )
                )

        for header_name in INFO_DISCLOSURE_HEADERS:
            value = response.headers.get(header_name)
            if value:
                result.findings.append(
                    Finding(
                        severity="info",
                        title=f"{header_name} header discloses version/software info",
                        description=f"{header_name}: {value}",
                        location=ctx.target,
                    )
                )

        self._check_cors(ctx, result)

    def _check_cors(self, ctx: ScanContext, result: AgentResult) -> None:
        cors_response = safe_get(
            ctx, ctx.target, cache=False, headers={"Origin": PROBE_ORIGIN}
        )
        if cors_response is None:
            return

        acao = cors_response.headers.get("Access-Control-Allow-Origin")
        acac = cors_response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if acao is None:
            return

        if acao == PROBE_ORIGIN and acac:
            result.findings.append(
                Finding(
                    severity="high",
                    title="CORS misconfiguration: arbitrary origin reflected with credentials allowed",
                    description=(
                        "The server reflects any Origin header back in Access-Control-Allow-Origin "
                        "while also setting Access-Control-Allow-Credentials: true, which lets any "
                        "website read authenticated responses on behalf of a victim's browser."
                    ),
                    location=ctx.target,
                    evidence={"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": "true"},
                )
            )
        elif acao == "*" and acac:
            result.findings.append(
                Finding(
                    severity="high",
                    title="CORS misconfiguration: wildcard origin with credentials allowed",
                    description=(
                        "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true "
                        "is invalid per the CORS spec and browsers should reject it, but misconfigured/legacy "
                        "clients or non-browser consumers may still trust it — treat as a misconfiguration to fix."
                    ),
                    location=ctx.target,
                )
            )
        elif acao == "*":
            result.findings.append(
                Finding(
                    severity="info",
                    title="CORS: wildcard Access-Control-Allow-Origin",
                    description="The API allows cross-origin reads from any origin (no credentials allowed).",
                    location=ctx.target,
                )
            )
        elif acao == PROBE_ORIGIN:
            result.findings.append(
                Finding(
                    severity="medium",
                    title="CORS: arbitrary origin reflected",
                    description=(
                        "The server reflects any Origin header back in Access-Control-Allow-Origin. "
                        "No credentials flag was set, but this still allows cross-origin reads of "
                        "non-credentialed responses from any site."
                    ),
                    location=ctx.target,
                )
            )


AGENT = HeadersCorsAgent()
