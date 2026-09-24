from nomore.config import Config
from nomore.models import Finding, Severity
from nomore.scan import ScanEngine
from nomore.scope import ScopeEngine
from nomore.reporting import render_markdown_report


def test_scope_engine_allows_included_domains_and_blocks_excluded_ones():
    scope = ScopeEngine(include=["*.example.com"], exclude=["admin.example.com"])

    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("admin.example.com") is False
    assert scope.is_in_scope("evil.com") is False


def test_finding_severity_and_evidence_are_serialized():
    finding = Finding(
        title="Weak CSP",
        severity=Severity.MEDIUM,
        confidence="medium",
        affected_asset="https://example.com",
        evidence=["missing directives"],
    )

    payload = finding.to_dict()
    assert payload["severity"] == "MEDIUM"
    assert payload["confidence"] == "medium"
    assert payload["evidence"] == ["missing directives"]


def test_markdown_report_renders_summary_and_findings():
    cfg = Config(target="example.com", scope={"include": ["*.example.com"]})
    finding = Finding(
        title="Missing security headers",
        severity=Severity.LOW,
        confidence="high",
        affected_asset="https://example.com",
        evidence=["X-Frame-Options missing"],
    )

    report = render_markdown_report(cfg, [finding])
    assert "# NOMORE Security Report" in report
    assert "Missing security headers" in report
    assert "example.com" in report


def test_scan_engine_supports_all_method_and_collects_finding_data():
    engine = ScanEngine()
    result = engine.run(target="example.com", method="all")

    assert result["target"] == "example.com"
    assert "all" in result["methods"]
    assert isinstance(result["findings"], list)
    assert result["summary"]["total_findings"] >= 0
