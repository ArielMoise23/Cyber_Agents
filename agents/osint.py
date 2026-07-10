import re
import socket

import requests

from agents.base import BaseAgent
from core.http_client import safe_get
from core.models import AgentResult, Finding, ScanContext

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

TECH_COOKIE_HINTS = {
    "phpsessid": "PHP",
    "laravel_session": "Laravel",
    "asp.net_sessionid": "ASP.NET",
    "jsessionid": "Java/J2EE",
    "django_language": "Django",
    "wordpress_": "WordPress",
    "csrftoken": "Django",
}
TECH_PATH_HINTS = {
    "/wp-content/": "WordPress",
    "/wp-includes/": "WordPress",
    "/sites/default/": "Drupal",
    "/typo3": "TYPO3",
    "/administrator/": "Joomla",
}


class OsintAgent(BaseAgent):
    name = "osint"
    display_name = "OSINT Overview"

    def _run(self, ctx: ScanContext, result: AgentResult) -> None:
        self._dns_lookup(ctx, result)
        self._whois_lookup(ctx, result)
        self._subdomain_enum(ctx, result)
        self._robots_and_sitemap(ctx, result)
        self._tech_fingerprint(ctx, result)
        self._search_footprint(ctx, result)

    def _dns_lookup(self, ctx: ScanContext, result: AgentResult) -> None:
        records: dict[str, list[str]] = {}
        try:
            import dns.resolver

            for rtype in DNS_RECORD_TYPES:
                try:
                    answers = dns.resolver.resolve(ctx.domain, rtype)
                    records[rtype] = [str(a) for a in answers]
                except Exception:
                    continue
        except ImportError:
            try:
                records["A"] = [socket.gethostbyname(ctx.domain)]
                result.findings.append(
                    Finding(
                        severity="info",
                        title="DNS lookup limited to A record",
                        description="dnspython not installed; only resolved the A record via socket.",
                        location=ctx.domain,
                    )
                )
            except OSError as exc:
                result.errors.append(f"DNS lookup failed: {exc}")
                return

        result.raw_data["dns_records"] = records
        for rtype, values in records.items():
            result.findings.append(
                Finding(
                    severity="info",
                    title=f"DNS {rtype} record(s)",
                    description=", ".join(values),
                    location=ctx.domain,
                )
            )

    def _whois_lookup(self, ctx: ScanContext, result: AgentResult) -> None:
        try:
            import whois

            data = whois.whois(ctx.domain)
            summary = {
                "registrar": getattr(data, "registrar", None),
                "creation_date": str(getattr(data, "creation_date", None)),
                "expiration_date": str(getattr(data, "expiration_date", None)),
            }
            result.raw_data["whois"] = summary
            result.findings.append(
                Finding(
                    severity="info",
                    title="WHOIS record retrieved",
                    description=f"Registrar: {summary['registrar']}, expires: {summary['expiration_date']}",
                    location=ctx.domain,
                )
            )
        except ImportError:
            result.findings.append(
                Finding(
                    severity="info",
                    title="WHOIS lookup skipped",
                    description="python-whois not installed.",
                    location=ctx.domain,
                )
            )
        except Exception as exc:  # noqa: BLE001 - WHOIS servers are flaky/rate-limited
            result.findings.append(
                Finding(
                    severity="info",
                    title="WHOIS lookup unavailable",
                    description=f"WHOIS query failed: {exc}",
                    location=ctx.domain,
                )
            )

    def _subdomain_enum(self, ctx: ScanContext, result: AgentResult) -> None:
        try:
            response = requests.get(
                f"https://crt.sh/?q=%25.{ctx.domain}&output=json", timeout=15
            )
            response.raise_for_status()
            entries = response.json()
        except Exception as exc:  # noqa: BLE001 - crt.sh is public and frequently flaky
            result.findings.append(
                Finding(
                    severity="info",
                    title="Certificate-transparency subdomain lookup unavailable",
                    description=f"crt.sh query failed: {exc}",
                    location=ctx.domain,
                )
            )
            return

        subdomains: set[str] = set()
        for entry in entries[:500]:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(ctx.domain):
                    subdomains.add(name)
        subdomains = set(sorted(subdomains)[:200])

        result.raw_data["subdomains"] = sorted(subdomains)
        if subdomains:
            result.findings.append(
                Finding(
                    severity="info",
                    title=f"{len(subdomains)} subdomain(s) found via certificate transparency",
                    description=", ".join(sorted(subdomains)[:25]) + (" ..." if len(subdomains) > 25 else ""),
                    location=ctx.domain,
                )
            )

    def _robots_and_sitemap(self, ctx: ScanContext, result: AgentResult) -> None:
        robots_resp = safe_get(ctx, f"{ctx.target}/robots.txt")
        sitemap_urls = {f"{ctx.target}/sitemap.xml"}

        if robots_resp is not None and robots_resp.status_code == 200:
            disallowed = []
            for line in robots_resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                        ctx.discovered_urls.add(ctx.target.rstrip("/") + path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_urls.add(line.split(":", 1)[1].strip())

            if disallowed:
                result.findings.append(
                    Finding(
                        severity="info",
                        title=f"robots.txt discloses {len(disallowed)} disallowed path(s)",
                        description=", ".join(disallowed[:20]),
                        location=f"{ctx.target}/robots.txt",
                    )
                )

        for sitemap_url in sitemap_urls:
            sitemap_resp = safe_get(ctx, sitemap_url)
            if sitemap_resp is None or sitemap_resp.status_code != 200:
                continue
            locs = SITEMAP_LOC_RE.findall(sitemap_resp.text)
            ctx.discovered_urls.update(locs)
            if locs:
                result.findings.append(
                    Finding(
                        severity="info",
                        title=f"Sitemap discloses {len(locs)} URL(s)",
                        description=sitemap_url,
                        location=sitemap_url,
                    )
                )

    def _tech_fingerprint(self, ctx: ScanContext, result: AgentResult) -> None:
        response = safe_get(ctx, ctx.target)
        if response is None:
            result.errors.append(f"Could not fetch {ctx.target} for tech fingerprinting.")
            return

        tech: set[str] = set()

        server = response.headers.get("Server")
        if server:
            tech.add(server)
        powered_by = response.headers.get("X-Powered-By")
        if powered_by:
            tech.add(powered_by)

        for cookie_name in response.cookies.keys():
            hint = TECH_COOKIE_HINTS.get(cookie_name.lower())
            if hint:
                tech.add(hint)

        body_lower = response.text.lower()
        for path_hint, name in TECH_PATH_HINTS.items():
            if path_hint in body_lower:
                tech.add(name)

        generator_match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            response.text,
            re.IGNORECASE,
        )
        if generator_match:
            tech.add(generator_match.group(1))

        ctx.tech_fingerprint.extend(sorted(tech))
        result.raw_data["tech_fingerprint"] = sorted(tech)
        if tech:
            result.findings.append(
                Finding(
                    severity="info",
                    title="Technology fingerprint",
                    description=", ".join(sorted(tech)),
                    location=ctx.target,
                )
            )

    def _search_footprint(self, ctx: ScanContext, result: AgentResult) -> None:
        try:
            from duckduckgo_search import DDGS

            with DDGS() as ddgs:
                hits = list(ddgs.text(f"site:{ctx.domain}", max_results=20))
        except Exception as exc:  # noqa: BLE001 - search backend is rate-limit prone
            result.findings.append(
                Finding(
                    severity="info",
                    title="Search-engine footprint unavailable",
                    description=f"duckduckgo_search query failed: {exc}",
                    location=ctx.domain,
                )
            )
            return

        result.raw_data["search_hits"] = [h.get("href", "") for h in hits]
        if hits:
            result.findings.append(
                Finding(
                    severity="info",
                    title=f"{len(hits)} indexed page(s) found via search-engine footprint",
                    description="; ".join(h.get("href", "") for h in hits[:10]),
                    location=ctx.domain,
                )
            )


AGENT = OsintAgent()
