import csv
import io
import json

from nomore.config import Config
from nomore.models import Finding, Severity
from nomore.reporting import (
    render_csv_report,
    render_html_report,
    render_json_report,
    render_markdown_report,
    render_report,
    render_sarif_report,
)

CONFIG = Config(target="example.test", profile="standard")


def sample():
    return [
        Finding(title="Low thing", severity=Severity.LOW, affected_asset="https://example.test", evidence=["x"]),
        Finding(title="High thing", severity=Severity.HIGH, affected_asset="https://example.test",
                affected_url="https://example.test/a", evidence=["y"], remediation="fix it", description="desc"),
    ]


def test_html_report_escapes_target_controlled_strings():
    hostile = Finding(
        title="<script>alert(1)</script>",
        severity=Severity.LOW,
        affected_asset="https://example.test",
        evidence=["Server: <img src=x onerror=alert(2)>"],
        remediation="<b>bold</b>",
    )
    report = render_html_report(Config(target="<i>t</i>", profile="<p>"), [hostile])
    assert "<script>alert(1)</script>" not in report
    assert "<img src=x" not in report
    assert "<i>t</i>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report


def test_html_report_handles_no_findings():
    assert "No findings recorded" in render_html_report(CONFIG, [])


def test_csv_report_quotes_fields_and_neutralises_formulas():
    tricky = Finding(
        title='Has, comma and "quotes"',
        severity=Severity.LOW,
        affected_asset="https://example.test",
        evidence=["=HYPERLINK(\"http://evil\")", "second"],
    )
    rows = list(csv.reader(io.StringIO(render_csv_report(CONFIG, [tricky]))))
    assert rows[0][:3] == ["title", "severity", "confidence"]
    assert rows[1][0] == 'Has, comma and "quotes"'
    assert rows[1][6].startswith("'=")  # formula prefix neutralised
    assert len(rows[1]) == len(rows[0])  # commas did not break the column layout


def test_sarif_levels_follow_severity_and_include_rules_and_fingerprints():
    payload = json.loads(render_sarif_report(CONFIG, sample()))
    run = payload["runs"][0]
    levels = {r["properties"]["severity"]: r["level"] for r in run["results"]}
    assert levels == {"HIGH": "error", "LOW": "note"}
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {"NOMORE/high-thing", "NOMORE/low-thing"}
    assert all("nomoreFingerprint/v1" in r["partialFingerprints"] for r in run["results"])
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.test/a"


def test_reports_list_highest_severity_first():
    markdown = render_markdown_report(CONFIG, sample())
    assert markdown.index("High thing") < markdown.index("Low thing")
    assert "- HIGH: 1" in markdown
    assert [f["title"] for f in json.loads(render_json_report(CONFIG, sample()))["findings"]][0] == "High thing"


def test_render_report_dispatches_every_format():
    for fmt in ("markdown", "json", "html", "sarif", "csv"):
        assert render_report(fmt, CONFIG, sample())
