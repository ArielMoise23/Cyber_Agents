import uuid
from dataclasses import dataclass

import requests

from core.models import ScanContext

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CyberAgentsScanner/1.0; +authorized-security-testing)"
}


def get_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session


def safe_get(
    ctx: ScanContext,
    url: str,
    cache: bool = True,
    **kwargs,
) -> requests.Response | None:
    """GET a URL through the shared session, swallowing network errors.

    Caches response bodies on ctx.response_cache so later agents (e.g.
    debug_leak) can scan bodies fetched by earlier agents without refetching.
    """
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    try:
        response = ctx.session.get(url, **kwargs)
    except requests.RequestException:
        return None

    if cache:
        try:
            ctx.response_cache[url] = response.text
        except Exception:
            pass
    return response


@dataclass
class SoftBaseline:
    status: int | None
    length: int | None
    content_type: str | None


def get_soft_404_baseline(ctx: ScanContext) -> SoftBaseline:
    """Fetch a definitely-nonexistent path to learn what the target's default fallback
    response looks like. Many apps — especially SPAs with client-side routing — return
    HTTP 200 for any path, so a bare status-code check can't tell a real page from the
    catch-all shell. Compare candidate responses against this baseline instead."""
    probe_url = ctx.target.rstrip("/") + f"/__nonexistent_{uuid.uuid4().hex[:12]}__"
    response = safe_get(ctx, probe_url, cache=False, allow_redirects=False)
    if response is None:
        return SoftBaseline(status=None, length=None, content_type=None)
    return SoftBaseline(
        status=response.status_code,
        length=len(response.content),
        content_type=response.headers.get("Content-Type"),
    )


def is_distinct_from_baseline(
    response: requests.Response, baseline: SoftBaseline, length_tolerance: int = 50
) -> bool:
    """True if a 200 response looks like a genuinely different page than the baseline
    fallback — either a different content-type (e.g. real JSON vs. the HTML SPA shell)
    or a content length that differs by more than length_tolerance bytes."""
    if baseline.status != 200 or baseline.length is None:
        return True

    response_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()
    baseline_type = (baseline.content_type or "").split(";")[0].strip()
    if response_type and baseline_type and response_type != baseline_type:
        return True

    return abs(len(response.content) - baseline.length) >= length_tolerance
