import re

from agents.base import BaseAgent
from core.http_client import safe_get
from core.models import AgentResult, Finding, ScanContext

AUTH_FORM_KEYWORDS = ["login", "signin", "sign-in", "logon", "register", "signup", "sign-up", "password", "reset"]
SESSION_COOKIE_NAME_HINTS = ["session", "sess", "token", "auth", "sid", "jwt"]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _form_is_auth_related(form: dict) -> bool:
    haystack = " ".join([form.get("action", ""), form.get("url", "")])
    haystack += " " + " ".join(inp.get("name", "") for inp in form.get("inputs", []))
    haystack = haystack.lower()
    return any(keyword in haystack for keyword in AUTH_FORM_KEYWORDS)


class AuthCollectorAgent(BaseAgent):
    name = "auth_collector"
    display_name = "Authentication Data Collector"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        self._collect_forms(ctx, result)
        self._collect_cookie_flags(ctx, result)
        self._collect_auth_scheme_hints(ctx, result)

    def _collect_forms(self, ctx: ScanContext, result: AgentResult) -> None:
        auth_forms = [f for f in ctx.discovered_forms if _form_is_auth_related(f)]
        result.raw_data["auth_forms"] = auth_forms

        for form in auth_forms:
            has_password_field = any(inp.get("type") == "password" for inp in form["inputs"])
            severity = "info"
            description = f"Method: {form['method'].upper()}, action: {form['action']}."
            if has_password_field and not form["has_csrf_field"]:
                severity = "medium"
                description += " Contains a password field but no CSRF-token-like hidden field was detected."

            result.findings.append(
                Finding(
                    severity=severity,
                    title="Authentication-related form discovered",
                    description=description,
                    location=form["url"],
                    evidence={"inputs": [i["name"] for i in form["inputs"]]},
                )
            )

    def _collect_cookie_flags(self, ctx: ScanContext, result: AgentResult) -> None:
        if ctx.target not in ctx.response_cache:
            safe_get(ctx, ctx.target)

        for cookie in ctx.session.cookies:
            name_lower = cookie.name.lower()
            if not any(hint in name_lower for hint in SESSION_COOKIE_NAME_HINTS):
                continue

            same_site = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
            issues = []
            if not cookie.secure and ctx.target.startswith("https"):
                issues.append("missing Secure flag")
            http_only = cookie.has_nonstandard_attr("HttpOnly") if hasattr(cookie, "has_nonstandard_attr") else False
            if not http_only:
                issues.append("missing HttpOnly flag")
            if not same_site:
                issues.append("missing SameSite attribute")

            if issues:
                result.findings.append(
                    Finding(
                        severity="medium",
                        title=f"Session-like cookie '{cookie.name}' has weak flags",
                        description=", ".join(issues) + ".",
                        location=ctx.target,
                    )
                )

    def _collect_auth_scheme_hints(self, ctx: ScanContext, result: AgentResult) -> None:
        for url, body in ctx.response_cache.items():
            for jwt_match in set(JWT_RE.findall(body)):
                result.findings.append(
                    Finding(
                        severity="medium",
                        title="Possible JWT exposed client-side",
                        description="A JWT-shaped token was found in a page/script response body — verify it does not carry sensitive claims and is not usable for privilege escalation.",
                        location=url,
                        evidence=jwt_match[:40] + "...",
                    )
                )


AGENT = AuthCollectorAgent()
