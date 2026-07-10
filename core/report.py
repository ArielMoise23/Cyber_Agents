import json
from datetime import datetime, timezone
from pathlib import Path

from core.models import ScanContext

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _report_stem(ctx: ScanContext) -> str:
    stamp = datetime.now(timezone.utc).strftime("%d-%m-%y_%H-%M")
    return f"{ctx.domain}_{stamp}_report"


def _to_dict(ctx: ScanContext, synthesis: str | None) -> dict:
    return {
        "target": ctx.target,
        "domain": ctx.domain,
        "agents": [
            {
                "agent": result.agent_name,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "finished_at": result.finished_at.isoformat() if result.finished_at else None,
                "findings": [
                    {
                        "severity": f.severity,
                        "title": f.title,
                        "description": f.description,
                        "location": f.location,
                        "evidence": f.evidence,
                    }
                    for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
                ],
                "errors": result.errors,
            }
            for result in ctx.results.values()
        ],
        "synthesis": synthesis,
    }


def save_json(ctx: ScanContext, synthesis: str | None, out_dir: str = "reports") -> Path:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    file_path = out_path / f"{_report_stem(ctx)}.json"
    file_path.write_text(json.dumps(_to_dict(ctx, synthesis), indent=2))
    return file_path


def render_markdown(ctx: ScanContext, synthesis: str | None) -> str:
    lines = [f"# Security Scan Report: {ctx.target}", ""]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(synthesis or "_LLM synthesis unavailable for this run._")
    lines.append("")

    for result in ctx.results.values():
        lines.append(f"## {result.agent_name}")
        if result.errors:
            lines.append("")
            lines.append("**Errors:** " + "; ".join(result.errors))
        if not result.findings:
            lines.append("")
            lines.append("_No findings._")
            lines.append("")
            continue

        lines.append("")
        lines.append("| Severity | Title | Location |")
        lines.append("|---|---|---|")
        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
            location = f.location or ""
            lines.append(f"| {f.severity} | {f.title} | {location} |")
        lines.append("")
        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
            lines.append(f"- **[{f.severity}] {f.title}** — {f.description}")
        lines.append("")

    return "\n".join(lines)


def save_markdown(ctx: ScanContext, synthesis: str | None, out_dir: str = "reports") -> Path:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    file_path = out_path / f"{_report_stem(ctx)}.md"
    file_path.write_text(render_markdown(ctx, synthesis))
    return file_path


def print_console_summary(ctx: ScanContext) -> None:
    print("\n" + "=" * 60)
    print(f"Scan summary for {ctx.target}")
    print("=" * 60)
    for result in ctx.results.values():
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        error_note = f" ({len(result.errors)} error(s))" if result.errors else ""
        print(
            f"  {result.agent_name:<20} "
            f"high={counts['high']} medium={counts['medium']} "
            f"low={counts['low']} info={counts['info']}{error_note}"
        )
    print("=" * 60 + "\n")
