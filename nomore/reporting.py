from __future__ import annotations

import csv
import html
import io
import json
import re
from typing import Iterable

from .config import Config
from .models import SEVERITY_ORDER, Finding

REPORT_FORMATS = ["markdown", "json", "html", "sarif", "csv"]


def _sorted(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: item.severity.rank, reverse=True)


def _counts(rows: list[Finding]) -> dict[str, int]:
    counts = {label: 0 for label in reversed(SEVERITY_ORDER)}
    for item in rows:
        counts[str(item.severity)] += 1
    return counts


def render_markdown_report(config: Config, findings: Iterable[Finding]) -> str:
    rows = _sorted(findings)
    lines = [
        "# NOMORE Security Report",
        "",
        f"- Target: {config.target}",
        f"- Profile: {config.profile}",
        "",
        "## Summary",
        "",
        f"Total findings: {len(rows)}",
        "",
    ]
    lines += [f"- {label}: {count}" for label, count in _counts(rows).items() if count]
    lines += ["", "## Findings", ""]

    if not rows:
        lines.append("No findings recorded for this target.")
        return "\n".join(lines) + "\n"

    for item in rows:
        lines.append(f"### {item.title}")
        lines.append(f"- Severity: {item.severity}")
        lines.append(f"- Confidence: {item.confidence}")
        lines.append(f"- Asset: {item.affected_asset or config.target}")
        if item.affected_url:
            lines.append(f"- URL: {item.affected_url}")
        if item.parameter:
            lines.append(f"- Parameter: {item.parameter}")
        if item.description:
            lines.append(f"- Description: {item.description}")
        if item.evidence:
            lines.append("- Evidence:")
            for evidence in item.evidence:
                lines.append(f"  - {evidence}")
        if item.remediation:
            lines.append(f"- Remediation: {item.remediation}")
        lines.append("")

    return "\n".join(lines) + "\n"


def render_json_report(config: Config, findings: Iterable[Finding]) -> str:
    payload = {
        "target": config.target,
        "profile": config.profile,
        "findings": [finding.to_dict() for finding in _sorted(findings)],
    }
    return json.dumps(payload, indent=2)


def render_html_report(config: Config, findings: Iterable[Finding]) -> str:
    """Render a standalone HTML report. Every dynamic value is HTML-escaped because
    findings can contain strings controlled by the scanned target."""
    esc = html.escape
    rows = _sorted(findings)
    items = []
    for item in rows:
        evidence = "".join(f"<li>{esc(line)}</li>" for line in item.evidence)
        items.append(
            "<li>"
            f"<strong>{esc(item.title)}</strong> "
            f"<span class=\"sev sev-{esc(str(item.severity).lower())}\">{esc(str(item.severity))}</span> "
            f"&mdash; {esc(item.affected_asset)}"
            + (f"<br><small>{esc(item.affected_url)}</small>" if item.affected_url else "")
            + (f"<ul>{evidence}</ul>" if evidence else "")
            + (f"<p><em>Remediation:</em> {esc(item.remediation)}</p>" if item.remediation else "")
            + "</li>"
        )
    body = "\n      ".join(items) or "<li>No findings recorded.</li>"
    summary = ", ".join(f"{esc(k)}: {v}" for k, v in _counts(rows).items() if v) or "none"
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>NOMORE Security Report</title>
    <style>
      body {{ font-family: system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }}
      .sev {{ font-size: .75rem; padding: .1rem .4rem; border-radius: .25rem; background: #eee; }}
      .sev-critical, .sev-high {{ background: #f8d7da; }} .sev-medium {{ background: #fff3cd; }}
      li {{ margin-bottom: 1rem; }}
    </style>
  </head>
  <body>
    <h1>NOMORE Security Report</h1>
    <p><strong>Target:</strong> {esc(config.target)}</p>
    <p><strong>Profile:</strong> {esc(config.profile)}</p>
    <p><strong>Findings:</strong> {len(rows)} ({summary})</p>
    <ul>
      {body}
    </ul>
  </body>
</html>
"""


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection (cells starting with = + - @)."""
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def render_csv_report(config: Config, findings: Iterable[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["title", "severity", "confidence", "affected_asset", "affected_url", "parameter", "evidence", "remediation"])
    for item in _sorted(findings):
        writer.writerow(
            [_csv_safe(str(value)) for value in (
                item.title, item.severity, item.confidence, item.affected_asset or config.target,
                item.affected_url, item.parameter, "; ".join(item.evidence), item.remediation,
            )]
        )
    return buffer.getvalue()


SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def _rule_id(title: str) -> str:
    return "NOMORE/" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def render_sarif_report(config: Config, findings: Iterable[Finding]) -> str:
    rows = _sorted(findings)
    rules: dict[str, dict] = {}
    results = []
    for item in rows:
        rule_id = _rule_id(item.title)
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": item.title,
            "shortDescription": {"text": item.title},
            "help": {"text": item.remediation or item.title},
        })
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(str(item.severity), "warning"),
            "message": {"text": item.description or item.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.affected_url or item.affected_asset or config.target}}}],
            "partialFingerprints": {"nomoreFingerprint/v1": item.fingerprint()},
            "properties": {"severity": str(item.severity), "confidence": item.confidence, "evidence": item.evidence},
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "NOMORE", "informationUri": "https://example.invalid/nomore", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2)


def render_report(fmt: str, config: Config, findings: Iterable[Finding]) -> str:
    renderers = {
        "markdown": render_markdown_report,
        "json": render_json_report,
        "html": render_html_report,
        "sarif": render_sarif_report,
        "csv": render_csv_report,
    }
    return renderers[fmt](config, findings)
