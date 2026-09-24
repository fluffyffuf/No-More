import socket
from datetime import datetime, timedelta, timezone

import pytest

from nomore.checks import (
    CheckContext,
    check_api,
    check_certs,
    check_cookies,
    check_cors,
    check_crawl,
    check_dns,
    check_headers,
    check_subdomains,
    check_technologies,
    check_tls,
    parse_ct_names,
    parse_set_cookie,
    probe_tls,
    summarize_certificate,
)
from nomore.client import FetchError, Response, SafeClient
from nomore.models import Severity
from nomore.scan import ScanEngine
from nomore.scope import ScopeEngine


class FakeClient:
    """Returns canned responses so header/CORS/TLS logic can be tested without a server."""

    def __init__(self, responses):
        self.responses = responses
        self.audit = []

    def get(self, url, headers=None):
        self.audit.append(url)
        response = self.responses.get(url) or next(iter(self.responses.values()))
        return response


def ctx_for(url, scope, client=None, **kwargs):
    return CheckContext(target=url, scope=scope, client=client or SafeClient(scope, rate_limit=1000), **kwargs)


def by_title(findings, title):
    matches = [f for f in findings if f.title == title]
    assert matches, f"no finding titled {title!r}; got {[f.title for f in findings]}"
    return matches


# -- against the local vulnerable app ----------------------------------------------
@pytest.fixture
def ctx(vuln_server, local_scope):
    return ctx_for(vuln_server["url"], local_scope)


def test_headers_check_finds_missing_headers_and_version_disclosure(ctx):
    findings = check_headers(ctx)
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Content-Type-Options header" in titles
    assert "Clickjacking protection missing" in titles
    assert "Server version disclosed" in titles
    assert "Missing HSTS header" not in titles  # plain HTTP target: HSTS is not applicable


def test_cookies_check_flags_session_cookie_without_flags(ctx):
    finding = by_title(check_cookies(ctx), "Cookie missing security attributes")[0]
    assert finding.parameter == "session"
    assert finding.severity == Severity.MEDIUM  # session-like name without HttpOnly
    assert "HttpOnly flag missing" in finding.evidence
    assert "SameSite attribute not set" in finding.evidence
    assert "Secure flag missing" not in finding.evidence  # target is plain HTTP


def test_cors_check_detects_reflected_origin_with_credentials(ctx):
    finding = by_title(check_cors(ctx), "CORS policy reflects arbitrary origins")[0]
    assert finding.severity == Severity.HIGH
    assert finding.confidence == "high"


def test_crawl_stays_on_host_and_never_follows_logout(vuln_server, local_scope):
    seen_before = len(vuln_server["seen"])
    context = ctx_for(vuln_server["url"], local_scope)
    finding = by_title(check_crawl(context), "Crawl inventory created")[0]

    assert "/api/v1/users" in finding.evidence
    assert "/reflect?q=hi" in finding.evidence
    assert "/logout" not in finding.evidence
    assert "form POST /login" in finding.evidence  # listed, never submitted
    assert "/logout" not in vuln_server["seen"][seen_before:]
    assert "/login" not in vuln_server["seen"][seen_before:]
    assert all("127.0.0.1" in entry["url"] for entry in context.client.audit)  # external link ignored


def test_technologies_check_reads_headers_and_meta_generator(ctx):
    ctx.crawl()
    finding = by_title(check_technologies(ctx), "Technology profile identified")[0]
    assert any(line.startswith("server:") for line in finding.evidence)
    assert "meta generator: VulnApp 1.0" in finding.evidence
    assert "VulnApp 1.0" in ctx.technologies


def test_api_check_finds_linked_api_routes_passively(vuln_server, local_scope):
    seen_before = len(vuln_server["seen"])
    findings = check_api(ctx_for(vuln_server["url"], local_scope, active=False))
    assert [f.title for f in findings] == ["API surface identified"]
    assert "/openapi.json" not in vuln_server["seen"][seen_before:]  # no guessing when passive


def test_api_check_probes_doc_paths_only_when_active(vuln_server, local_scope):
    findings = check_api(ctx_for(vuln_server["url"], local_scope, active=True))
    assert "API documentation publicly exposed" in {f.title for f in findings}


def test_active_probe_is_still_scope_checked(vuln_server, local_scope):
    context = ctx_for(vuln_server["url"], local_scope, active=True)
    check_api(context)
    assert all("127.0.0.1" in entry["url"] for entry in context.client.audit)


# -- header logic with canned responses ---------------------------------------------
def https_home(headers):
    return Response("https://example.test/", 200, headers, b"<html></html>")


def test_hsts_and_x_powered_by_on_https():
    scope = ScopeEngine(["example.test"], strict=True)
    home = https_home([("Content-Type", "text/html"), ("X-Powered-By", "Express")])
    findings = check_headers(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home})))
    titles = {f.title for f in findings}
    assert "Missing HSTS header" in titles
    assert "Technology disclosed via X-Powered-By" in titles


def test_csp_frame_ancestors_satisfies_clickjacking_protection():
    scope = ScopeEngine(["example.test"], strict=True)
    home = https_home([("Content-Security-Policy", "frame-ancestors 'none'")])
    findings = check_headers(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home})))
    assert "Clickjacking protection missing" not in {f.title for f in findings}
    assert "Missing Content-Security-Policy header" not in {f.title for f in findings}


def test_blocked_out_of_scope_redirect_is_reported():
    scope = ScopeEngine(["example.test"], strict=True)
    home = Response("https://example.test/", 302, [("Location", "https://other.test/")], b"", blocked_redirect="https://other.test/")
    findings = check_headers(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home})))
    finding = by_title(findings, "Redirect to out-of-scope host not followed")[0]
    assert "did not contact" in finding.evidence[1]


@pytest.mark.parametrize(
    "headers, expected",
    [
        ([("Access-Control-Allow-Origin", "*")], "CORS policy allows any origin (wildcard)"),
        ([("Access-Control-Allow-Origin", "null"), ("Access-Control-Allow-Credentials", "true")],
         "CORS policy trusts the 'null' origin with credentials"),
    ],
)
def test_cors_variants(headers, expected):
    scope = ScopeEngine(["example.test"], strict=True)
    home = Response("https://example.test/", 200, headers, b"")
    findings = check_cors(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home})))
    assert [f.title for f in findings] == [expected]


def test_cors_ignores_strict_policy():
    scope = ScopeEngine(["example.test"], strict=True)
    home = Response("https://example.test/", 200, [("Access-Control-Allow-Origin", "https://app.example.test")], b"")
    assert check_cors(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home}))) == []


def test_cookie_parsing_and_secure_flag_on_https():
    assert parse_set_cookie("id=1; Path=/; Secure; HttpOnly; SameSite=Lax") == {
        "name": "id",
        "attributes": {"path": "/", "secure": "", "httponly": "", "samesite": "Lax"},
    }
    scope = ScopeEngine(["example.test"], strict=True)
    home = https_home([("Set-Cookie", "theme=dark; HttpOnly; SameSite=None")])
    findings = check_cookies(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home})))
    finding = by_title(findings, "Cookie missing security attributes")[0]
    assert finding.severity == Severity.LOW  # not a session-looking name
    assert "Secure flag missing" in finding.evidence
    assert "SameSite=None without Secure" in finding.evidence


def test_hardened_cookie_produces_no_finding():
    scope = ScopeEngine(["example.test"], strict=True)
    home = https_home([("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Strict")])
    assert check_cookies(ctx_for("https://example.test/", scope, FakeClient({"https://example.test/": home}))) == []


# -- tls / certs --------------------------------------------------------------------
def fmt_cert_time(moment):
    return f"{moment:%b} {moment.day:2d} {moment:%H:%M:%S} {moment:%Y} GMT"


def make_cert(days_left):
    expires = datetime.now(timezone.utc) + timedelta(days=days_left, hours=1)
    return {
        "notAfter": fmt_cert_time(expires),
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.test"), ("DNS", "www.example.test")),
    }


def tls_ctx(prober):
    scope = ScopeEngine(["example.test"], strict=True)
    return ctx_for("https://example.test", scope, FakeClient({}), tls_prober=prober)


def test_certificate_summary_parses_expiry_issuer_and_sans():
    summary = summarize_certificate(make_cert(40))
    assert summary["days_left"] == 40
    assert summary["issuer"] == "Test CA"
    assert summary["sans"] == ["example.test", "www.example.test"]


def test_healthy_certificate_only_yields_inventory():
    context = tls_ctx(lambda *a: {"version": "TLSv1.3", "cipher": "X", "cert": make_cert(200), "verify_error": None})
    assert [f.title for f in check_certs(context)] == ["Certificate inventory reviewed"]
    assert [f.title for f in check_tls(context)] == ["TLS protocol negotiated"]


@pytest.mark.parametrize("days, severity", [(5, Severity.MEDIUM), (25, Severity.LOW)])
def test_expiring_certificate_is_flagged(days, severity):
    context = tls_ctx(lambda *a: {"version": "TLSv1.3", "cipher": "X", "cert": make_cert(days), "verify_error": None})
    finding = by_title(check_certs(context), "TLS certificate expires soon")[0]
    assert finding.severity == severity


def test_expired_certificate_is_high():
    context = tls_ctx(lambda *a: {"version": "TLSv1.3", "cipher": "X", "cert": make_cert(-3), "verify_error": None})
    assert by_title(check_certs(context), "TLS certificate expired")[0].severity == Severity.HIGH


def test_verification_failure_and_legacy_protocol_are_reported():
    context = tls_ctx(lambda *a: {"version": "TLSv1", "cipher": "X", "cert": None, "verify_error": "certificate has expired"})
    titles = {f.title: f for f in check_tls(context)}
    assert titles["TLS certificate failed verification"].evidence == ["certificate has expired"]
    assert "Deprecated TLS protocol negotiated" in titles


def test_tls_check_on_plain_http_target_says_not_evaluated(vuln_server, local_scope):
    findings = check_tls(ctx_for(vuln_server["url"], local_scope))
    assert [f.title for f in findings] == ["TLS not evaluated: target uses plain HTTP"]


def test_probe_tls_against_non_tls_port_raises_fetch_error(vuln_server):
    with pytest.raises(FetchError):
        probe_tls("127.0.0.1", vuln_server["port"], timeout=3)


# -- dns / subdomains ------------------------------------------------------------------
def test_dns_check_resolves_localhost_and_flags_private_addresses():
    scope = ScopeEngine(["localhost"], strict=True)
    findings = check_dns(ctx_for("http://localhost:1", scope))
    assert findings and any("localhost resolves to" in line for line in findings[0].evidence)
    assert any(line.startswith("private/loopback") for line in findings[0].evidence)


def test_dns_failure_becomes_fetch_error(monkeypatch):
    def boom(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    scope = ScopeEngine(["example.test"], strict=True)
    with pytest.raises(FetchError):
        check_dns(ctx_for("https://example.test", scope))


def test_parse_ct_names_filters_scope_wildcards_and_lookalikes():
    scope = ScopeEngine(["*.example.test"], ["admin.example.test"], strict=True)
    records = [
        {"name_value": "a.example.test\n*.b.example.test"},
        {"name_value": "admin.example.test"},
        {"name_value": "evil.com\nexample.test.evil.com"},
        {"common_name": "www.example.test", "name_value": ""},
    ]
    names, dropped = parse_ct_names(records, "example.test", scope)
    assert names == ["a.example.test", "b.example.test", "www.example.test"]
    assert dropped == 1


def test_subdomains_check_uses_injected_ct_source_and_never_contacts_hosts():
    scope = ScopeEngine(["*.example.test"], ["admin.example.test"], strict=True)
    client = FakeClient({})
    context = ctx_for("https://example.test", scope, client,
                      ct_fetcher=lambda d: [{"name_value": "api.example.test\nadmin.example.test"}])
    finding = by_title(check_subdomains(context), "Subdomain candidates identified")[0]
    assert "api.example.test" in finding.evidence
    assert any("excluded because they are out of scope" in line for line in finding.evidence)
    assert context.discovered_hosts == {"api.example.test"}
    assert client.audit == []


def test_subdomains_check_skips_ip_targets(vuln_server, local_scope):
    assert check_subdomains(ctx_for(vuln_server["url"], local_scope, ct_fetcher=lambda d: 1 / 0)) == []


# -- engine resilience ---------------------------------------------------------------------
def test_one_failing_check_does_not_abort_the_scan(vuln_server, local_scope):
    def broken_ct(domain):
        raise FetchError("CT service down")

    scope = ScopeEngine(["localhost", "127.0.0.1"], strict=True)
    engine = ScanEngine(scope, ct_fetcher=broken_ct)
    result = engine.run(target=f"http://localhost:{vuln_server['port']}", method="recon", rate_limit=1000)
    assert any(e["method"] == "subdomains" and "CT service down" in e["error"] for e in result["errors"])
    assert any(f["title"].startswith("Missing") for f in result["findings"])  # later checks still ran


def test_full_scan_of_fixture_reports_expected_findings_sorted_by_severity(vuln_server, local_scope):
    result = ScanEngine(local_scope).run(target=vuln_server["url"], method="all", rate_limit=1000)
    titles = {f["title"] for f in result["findings"]}
    assert {"CORS policy reflects arbitrary origins", "Cookie missing security attributes",
            "Crawl inventory created", "API surface identified", "Technology profile identified"} <= titles
    ranks = [["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(f["severity"]) for f in result["findings"]]
    assert ranks == sorted(ranks, reverse=True)
    assert result["summary"]["severity_counts"]["HIGH"] >= 1
    assert result["technologies"]


def test_engine_deduplicates_repeated_findings():
    from nomore.models import Finding
    from nomore.scan import dedupe_findings

    a = Finding(title="X", severity=Severity.LOW, affected_asset="a", evidence=["one"])
    b = Finding(title="X", severity=Severity.HIGH, affected_asset="a", evidence=["one", "two"])
    merged = dedupe_findings([a, b])
    assert len(merged) == 1
    assert merged[0].severity == Severity.HIGH
    assert merged[0].evidence == ["one", "two"]
