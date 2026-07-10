from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests


@dataclass
class Finding:
    severity: str  # "info" | "low" | "medium" | "high"
    title: str
    description: str
    location: str | None = None
    evidence: dict | str | None = None


@dataclass
class AgentResult:
    agent_name: str
    findings: list[Finding] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None


@dataclass
class ScanContext:
    target: str
    domain: str
    session: requests.Session
    discovered_urls: set[str] = field(default_factory=set)
    discovered_forms: list[dict] = field(default_factory=list)
    discovered_js_files: set[str] = field(default_factory=set)
    discovered_endpoints: set[str] = field(default_factory=set)
    response_cache: dict[str, str] = field(default_factory=dict)
    tech_fingerprint: list[str] = field(default_factory=list)
    results: dict[str, AgentResult] = field(default_factory=dict)
    options: dict = field(default_factory=dict)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
