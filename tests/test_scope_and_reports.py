import pytest

from nomore.config import Config
from nomore.models import Finding, Severity
from nomore.reporting import render_markdown_report
from nomore.scan import ScanEngine
from nomore.scope import ScopeEngine, ScopeError, host_from_target


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
    assert len(payload["fingerprint"]) == 16


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


def test_scan_engine_runs_real_checks_and_collects_finding_data(vuln_server, local_scope):
    engine = ScanEngine(local_scope, ct_fetcher=lambda domain: [])
    result = engine.run(target=vuln_server["url"], method="all", rate_limit=1000)

    assert result["target"] == vuln_server["url"]
    assert result["methods"] == ScanEngine.METHOD_CATALOG["all"]
    assert result["errors"] == []
    assert result["summary"]["total_findings"] == len(result["findings"]) > 0
    assert result["requests_made"] > 0


# -- scope hardening ---------------------------------------------------------------
def test_strict_scope_with_no_includes_authorizes_nothing():
    assert ScopeEngine(strict=True).is_in_scope("example.com") is False
    assert ScopeEngine().is_in_scope("example.com") is True  # legacy, non-strict behaviour


def test_default_config_has_no_authorized_scope():
    assert Config().scope["include"] == []


def test_host_from_target_handles_urls_ports_and_ipv6():
    assert host_from_target("https://Api.Example.com:8443/path?q=1") == "api.example.com"
    assert host_from_target("example.com:8080") == "example.com"
    assert host_from_target("example.com") == "example.com"
    assert host_from_target("http://[::1]:8000/") == "::1"


def test_scope_handles_ipv6_and_ports():
    scope = ScopeEngine(include=["::1", "*.example.com"], strict=True)
    assert scope.is_target_in_scope("http://[::1]:8000/") is True
    assert scope.is_target_in_scope("https://a.example.com:8443") is True
    assert scope.is_target_in_scope("https://example.org") is False


def test_scope_does_not_match_lookalike_suffixes():
    scope = ScopeEngine(include=["example.com"], strict=True)
    assert scope.is_in_scope("notexample.com") is False
    assert scope.is_in_scope("example.com.evil.io") is False


def test_engine_refuses_out_of_scope_target_before_any_request(vuln_server):
    scope = ScopeEngine(include=["*.example.com"], strict=True)
    before = len(vuln_server["seen"])
    with pytest.raises(ScopeError):
        ScanEngine(scope).run(target=vuln_server["url"], method="headers")
    assert len(vuln_server["seen"]) == before


def test_unknown_method_is_rejected(local_scope):
    with pytest.raises(ValueError):
        ScanEngine(local_scope).run(target="http://127.0.0.1", method="nope")


def test_single_module_method_runs_only_that_module():
    assert ScanEngine.methods_for("cors") == ["cors"]
