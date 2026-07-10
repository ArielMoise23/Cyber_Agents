import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.http_client import safe_get
from core.models import ScanContext

ID_PARAM_NAME_RE = re.compile(r"(?:^|[_-])id$|id$", re.IGNORECASE)
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
NUMERIC_PATH_SEGMENT_RE = re.compile(r"/(\d+)(?:/|$)")

JS_ENDPOINT_PATTERNS = [
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-/{}.]+)["']"""),
    re.compile(r"""["'](/v[0-9]+/[a-zA-Z0-9_\-/{}.]+)["']"""),
]


def _same_origin(url: str, origin_netloc: str) -> bool:
    return urlparse(url).netloc == origin_netloc


def crawl(ctx: ScanContext, max_pages: int = 25, max_depth: int = 2) -> None:
    """Same-origin BFS crawl seeded from ctx.target and any already-discovered URLs.

    Populates ctx.discovered_urls / discovered_forms / discovered_js_files.
    Idempotent: safe to call once per scan (guarded by ctx.options flag).
    """
    if ctx.options.get("_crawl_done"):
        return
    ctx.options["_crawl_done"] = True

    origin_netloc = urlparse(ctx.target).netloc
    seeds = {ctx.target} | {u for u in ctx.discovered_urls if _same_origin(u, origin_netloc)}
    queue: deque[tuple[str, int]] = deque((url, 0) for url in seeds)
    visited: set[str] = set()

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        response = safe_get(ctx, url)
        if response is None or "text/html" not in response.headers.get("Content-Type", "text/html"):
            continue

        ctx.discovered_urls.add(url)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            ctx.discovered_forms.append(parse_form(form, url))

        for script in soup.find_all("script", src=True):
            js_url = urljoin(url, script["src"])
            if _same_origin(js_url, origin_netloc):
                ctx.discovered_js_files.add(js_url)

        for anchor in soup.find_all("a", href=True):
            next_url = urljoin(url, anchor["href"]).split("#")[0]
            if _same_origin(next_url, origin_netloc) and next_url not in visited:
                ctx.discovered_urls.add(next_url)
                if len(visited) + len(queue) < max_pages:
                    queue.append((next_url, depth + 1))


def parse_form(form_tag, page_url: str) -> dict:
    inputs = []
    for tag in form_tag.find_all(["input", "textarea", "select"]):
        inputs.append({
            "name": tag.get("name", ""),
            "type": tag.get("type", "text") if tag.name == "input" else tag.name,
        })

    has_csrf_field = any(
        "csrf" in (inp["name"] or "").lower() or "token" in (inp["name"] or "").lower()
        for inp in inputs
    )

    return {
        "url": page_url,
        "action": urljoin(page_url, form_tag.get("action", "")),
        "method": form_tag.get("method", "get").lower(),
        "inputs": inputs,
        "has_csrf_field": has_csrf_field,
    }


def extract_js_endpoints(js_text: str) -> set[str]:
    endpoints: set[str] = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        endpoints.update(pattern.findall(js_text))
    return endpoints


def extract_id_like_params(url: str) -> list[dict]:
    """Find URL query params / path segments that look like object references."""
    candidates: list[dict] = []
    parsed = urlparse(url)

    for match in NUMERIC_PATH_SEGMENT_RE.finditer(parsed.path):
        candidates.append({"url": url, "kind": "path_segment", "value": match.group(1)})

    for uuid_match in UUID_RE.finditer(url):
        candidates.append({"url": url, "kind": "uuid", "value": uuid_match.group(0)})

    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            if ID_PARAM_NAME_RE.search(name) and value.isdigit():
                candidates.append({"url": url, "kind": "query_param", "name": name, "value": value})

    return candidates
