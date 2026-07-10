from agents.base import BaseAgent
from core.crawler import extract_js_endpoints
from core.http_client import get_soft_404_baseline, is_distinct_from_baseline, safe_get
from core.models import AgentResult, Finding, ScanContext

MAX_JS_FILES = 25
MAX_JS_BYTES = 2_000_000

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/swagger-ui.html", "/swagger/index.html",
    "/openapi.json", "/api-docs", "/api/swagger.json",
]


class ApiCollectorAgent(BaseAgent):
    name = "api_collector"
    display_name = "API Endpoint Collector"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        endpoints: set[str] = set()

        for js_url in list(ctx.discovered_js_files)[:MAX_JS_FILES]:
            response = safe_get(ctx, js_url)
            if response is None or len(response.content) > MAX_JS_BYTES:
                continue
            found = extract_js_endpoints(response.text)
            if found:
                endpoints.update(found)
                result.findings.append(
                    Finding(
                        severity="info",
                        title=f"{len(found)} API endpoint reference(s) found in JS",
                        description=", ".join(sorted(found)[:15]),
                        location=js_url,
                    )
                )

        baseline = get_soft_404_baseline(ctx)
        for path in COMMON_API_PATHS:
            url = ctx.target.rstrip("/") + path
            response = safe_get(ctx, url, cache=False, allow_redirects=False)
            if response is not None and response.status_code == 200 and is_distinct_from_baseline(response, baseline):
                endpoints.add(path)
                is_docs = any(k in path for k in ("swagger", "openapi", "api-docs"))
                result.findings.append(
                    Finding(
                        severity="low" if is_docs else "info",
                        title=f"Common API path responded: {path}",
                        description=f"HTTP {response.status_code} at {path}."
                        + (" This may expose API documentation/schema publicly." if is_docs else ""),
                        location=url,
                    )
                )

        ctx.discovered_endpoints.update(endpoints)
        ctx.discovered_urls.update(ctx.target.rstrip("/") + e if e.startswith("/") else e for e in endpoints)
        result.raw_data["endpoints"] = sorted(endpoints)


AGENT = ApiCollectorAgent()
