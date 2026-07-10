from agents.base import BaseAgent
from core.crawler import extract_id_like_params
from core.http_client import safe_get
from core.models import AgentResult, Finding, ScanContext

MAX_ACTIVE_PROBE_CANDIDATES = 5
ADJACENT_OFFSETS = [-1, 1]


def _bump_numeric(url: str, kind: str, name: str | None, old_value: str, new_value: str) -> str:
    if kind == "query_param" and name:
        return url.replace(f"{name}={old_value}", f"{name}={new_value}")
    return url.replace(f"/{old_value}", f"/{new_value}", 1)


class IdorAgent(BaseAgent):
    name = "idor"
    display_name = "IDOR Detection"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        all_urls = ctx.discovered_urls | ctx.discovered_endpoints
        candidates: list[dict] = []
        for url in all_urls:
            candidates.extend(extract_id_like_params(url))

        if not candidates:
            return

        for candidate in candidates:
            result.findings.append(
                Finding(
                    severity="info",
                    title="Potential IDOR-prone parameter",
                    description=f"URL contains an object-reference-like value ({candidate['kind']}: {candidate['value']}).",
                    location=candidate["url"],
                )
            )

        if ctx.options.get("skip_active_idor"):
            return

        numeric_candidates = [c for c in candidates if c["value"].isdigit()][:MAX_ACTIVE_PROBE_CANDIDATES]
        for candidate in numeric_candidates:
            self._probe_adjacent(ctx, result, candidate)

    def _probe_adjacent(self, ctx: ScanContext, result: AgentResult, candidate: dict) -> None:
        url = candidate["url"]
        old_value = candidate["value"]
        name = candidate.get("name")

        baseline = safe_get(ctx, url, cache=False)
        if baseline is None:
            return

        for offset in ADJACENT_OFFSETS:
            new_value = str(int(old_value) + offset)
            if new_value.startswith("-"):
                continue
            probe_url = _bump_numeric(url, candidate["kind"], name, old_value, new_value)
            if probe_url == url:
                continue

            probe_resp = safe_get(ctx, probe_url, cache=False)
            if probe_resp is None:
                continue

            if probe_resp.status_code in (403, 404) or probe_resp.status_code != baseline.status_code:
                continue

            length_delta = abs(len(probe_resp.content) - len(baseline.content))
            if length_delta > 0 and length_delta / max(len(baseline.content), 1) > 0.05:
                result.findings.append(
                    Finding(
                        severity="medium",
                        title="Potential IDOR — adjacent ID returned distinct content, requires manual verification",
                        description=(
                            f"Requesting {url} with the ID changed from {old_value} to {new_value} "
                            f"(same session, same status code {probe_resp.status_code}) returned "
                            "materially different content. This is a heuristic signal only — confirm "
                            "manually whether this exposes another user's/object's data."
                        ),
                        location=probe_url,
                        evidence={"baseline_url": url, "probe_url": probe_url},
                    )
                )


AGENT = IdorAgent()
