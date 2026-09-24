from __future__ import annotations

import json
from typing import Iterable

from .config import Config
from .models import Finding


def render_markdown_report(config: Config, findings: Iterable[Finding]) -> str:
    rows = list(findings)
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
        "## Findings",
        "",
    ]

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
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)


def render_html_report(config: Config, findings: Iterable[Finding]) -> str:
    rows = "\n".join(
        f"<li><strong>{item.title}</strong> ({item.severity}) - {item.affected_asset}</li>"
        for item in findings
    )
    return f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>NOMORE Security Report</title>
  </head>
  <body>
    <h1>NOMORE Security Report</h1>
    <p><strong>Target:</strong> {config.target}</p>
    <p><strong>Profile:</strong> {config.profile}</p>
    <ul>
      {rows or '<li>No findings recorded.</li>'}
    </ul>
  </body>
</html>
"""


def render_sarif_report(config: Config, findings: Iterable[Finding]) -> str:
    results = []
    for item in findings:
        results.append({
            "ruleId": item.title,
            "level": "warning",
            "message": {"text": item.description or item.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.affected_asset or config.target}}}],
            "properties": {"severity": str(item.severity), "confidence": item.confidence},
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "NOMORE", "informationUri": "https://example.invalid/nomore"}},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2)
