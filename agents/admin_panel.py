import concurrent.futures

from agents.base import BaseAgent
from core.http_client import get_soft_404_baseline, is_distinct_from_baseline, safe_get
from core.models import AgentResult, Finding, ScanContext
from core.wordlists import load_wordlist

MAX_WORKERS = 10

CMS_PATH_HINTS = {
    "WordPress": ["/wp-admin", "/wp-admin/", "/wp-login.php"],
    "Joomla": ["/administrator", "/administrator/", "/administrator/index.php"],
    "Drupal": ["/user/login"],
}


def _prioritized_paths(all_paths: list[str], tech_fingerprint: list[str]) -> list[str]:
    priority: list[str] = []
    for tech in tech_fingerprint:
        for cms, paths in CMS_PATH_HINTS.items():
            if cms.lower() in tech.lower():
                priority.extend(p for p in paths if p in all_paths)

    rest = [p for p in all_paths if p not in priority]
    return priority + rest


class AdminPanelAgent(BaseAgent):
    name = "admin_panel"
    display_name = "Admin Panel Discovery"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        baseline = get_soft_404_baseline(ctx)
        paths = _prioritized_paths(load_wordlist("admin_paths"), ctx.tech_fingerprint)
        found: list[dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    safe_get, ctx, ctx.target.rstrip("/") + path, False, allow_redirects=False
                ): path
                for path in paths
            }
            for future in concurrent.futures.as_completed(futures):
                path = futures[future]
                response = future.result()
                if response is None:
                    continue
                found.append({"path": path, "response": response})

        for item in found:
            path, response = item["path"], item["response"]
            url = ctx.target.rstrip("/") + path

            if response.status_code in (401, 403):
                result.findings.append(
                    Finding(
                        severity="low",
                        title=f"Possible admin/management interface found (access controlled): {path}",
                        description=f"HTTP {response.status_code} at {path} — path exists but requires authorization.",
                        location=url,
                    )
                )
            elif response.status_code in (301, 302, 303, 307, 308):
                redirect_target = response.headers.get("Location", "")
                if any(k in redirect_target.lower() for k in ("login", "admin", "auth")):
                    result.findings.append(
                        Finding(
                            severity="low",
                            title=f"Redirect to login/admin from {path}",
                            description=f"HTTP {response.status_code} redirect to {redirect_target}.",
                            location=url,
                        )
                    )
            elif response.status_code == 200 and is_distinct_from_baseline(response, baseline):
                if self._confirm_distinct(ctx, url, baseline):
                    result.findings.append(
                        Finding(
                            severity="medium",
                            title=f"Admin/management path found: {path}",
                            description=f"HTTP 200 at {path}, distinct from the site's soft-404 baseline.",
                            location=url,
                        )
                    )

        result.raw_data["paths_checked"] = len(paths)

    @staticmethod
    def _confirm_distinct(ctx: ScanContext, url: str, baseline) -> bool:
        """Re-fetch sequentially (outside the thread pool) to rule out transient/concurrency
        noise — e.g. a target under scan load returning truncated chunked/gzip responses that
        look 'distinct' from the baseline only because of scanner-induced pressure, not a real
        difference in content served."""
        confirm_resp = safe_get(ctx, url, cache=False, allow_redirects=False)
        if confirm_resp is None or confirm_resp.status_code != 200:
            return False
        return is_distinct_from_baseline(confirm_resp, baseline)


AGENT = AdminPanelAgent()
