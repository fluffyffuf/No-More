import json

import pytest

from nomore.cli import main
from nomore.database import ScanDatabase


@pytest.fixture
def home(nomore_home):
    return nomore_home


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def authorize(capsys):
    assert run(capsys, "scope", "add", "127.0.0.1")[0] == 0


def test_scan_refuses_when_no_scope_is_configured(capsys, home, vuln_server):
    before = len(vuln_server["seen"])
    code, out, err = run(capsys, "scan", vuln_server["url"], "--rate", "1000")
    assert code == 2
    assert "out of scope" in err and "nomore scope add" in err
    assert len(vuln_server["seen"]) == before  # nothing was sent
    assert ScanDatabase().list_scans() == []


def test_scan_refuses_targets_outside_the_configured_scope(capsys, home, vuln_server):
    run(capsys, "scope", "add", "*.example.test")
    before = len(vuln_server["seen"])
    assert run(capsys, "scan", vuln_server["url"], "--rate", "1000")[0] == 2
    assert len(vuln_server["seen"]) == before


def test_scope_exclude_overrides_include(capsys, home, vuln_server):
    authorize(capsys)
    run(capsys, "scope", "exclude", "127.0.0.1")
    assert run(capsys, "scan", vuln_server["url"], "--rate", "1000")[0] == 2
    _, out, _ = run(capsys, "scope", "list")
    assert "- 127.0.0.1" in out and "Excluded:" in out
    run(capsys, "scope", "remove", "127.0.0.1")
    assert "No entries configured" in run(capsys, "scope", "list")[1]


def test_authorized_scan_runs_saves_history_and_prints_summary(capsys, home, vuln_server):
    authorize(capsys)
    code, out, err = run(capsys, "scan", vuln_server["url"], "deep", "--profile", "deep", "--rate", "1000")
    assert code == 0, err
    assert "Total findings:" in out and "CORS policy reflects arbitrary origins" in out
    scans = ScanDatabase().list_scans()
    assert len(scans) == 1 and scans[0]["profile"] == "deep"
    assert scans[0]["scan_id"][:8] in run(capsys, "history")[1]


def test_no_save_flag_skips_history(capsys, home, vuln_server):
    authorize(capsys)
    assert run(capsys, "scan", vuln_server["url"], "headers", "--rate", "1000", "--no-save")[0] == 0
    assert ScanDatabase().list_scans() == []


@pytest.mark.parametrize("threshold, expected", [("high", 1), ("HIGH", 1), ("medium", 1), ("critical", 0)])
def test_fail_on_sets_exit_code_and_is_case_insensitive(capsys, home, vuln_server, threshold, expected):
    authorize(capsys)
    code, _, err = run(capsys, "--quiet", "scan", vuln_server["url"], "all", "--rate", "1000", "--fail-on", threshold)
    assert code == expected, err


def test_unreachable_target_is_incomplete_not_a_clean_pass(capsys, home):
    authorize(capsys)
    code, out, err = run(capsys, "--quiet", "scan", "http://127.0.0.1:9", "all", "--rate", "1000", "--fail-on", "high")
    assert code == 3  # never 0: a dead target must not look like "no high findings"
    assert "failed" in err and "Scan incomplete" in err  # reported even with --quiet


def test_report_formats_from_latest_and_specific_scan(capsys, home, vuln_server, tmp_path):
    authorize(capsys)
    run(capsys, "scan", vuln_server["url"], "all", "--rate", "1000")
    scan_id = ScanDatabase().get_scan("latest")["scan_id"]

    code, out, _ = run(capsys, "report", "--format", "json")
    assert code == 0 and json.loads(out)["target"] == vuln_server["url"]
    assert "<!doctype html>" in run(capsys, "report", "--format", "html", "--scan", scan_id[:8])[1]
    assert json.loads(run(capsys, "report", "--format", "sarif")[1])["version"] == "2.1.0"
    assert run(capsys, "report", "--format", "csv")[1].startswith("title,severity")

    target = tmp_path / "out" / "report.md"
    assert run(capsys, "report", "--output", str(target))[0] == 0
    assert "# NOMORE Security Report" in target.read_text()


def test_report_without_any_scan_explains_what_to_do(capsys, home):
    code, _, err = run(capsys, "report")
    assert code == 1 and "nomore scan" in err


def test_diff_between_identical_scans_shows_no_changes(capsys, home, vuln_server):
    authorize(capsys)
    for _ in range(2):
        run(capsys, "scan", vuln_server["url"], "all", "--rate", "1000")
    code, out, _ = run(capsys, "diff")
    assert code == 0 and "New findings: 0" in out and "Fixed findings: 0" in out and "Unchanged: " in out


def test_diff_needs_two_scans_and_warns_about_incomplete_ones(capsys, home, vuln_server):
    authorize(capsys)
    assert run(capsys, "diff")[0] == 1
    run(capsys, "scan", vuln_server["url"], "all", "--rate", "1000")
    run(capsys, "scan", "http://127.0.0.1:9", "all", "--rate", "1000", "--no-save")  # not saved
    run(capsys, "scan", vuln_server["url"], "all", "--rate", "1000")
    assert run(capsys, "diff")[0] == 0
    assert run(capsys, "diff", "only-one-id")[0] == 2


def test_module_commands_print_json_and_are_scope_checked(capsys, home, vuln_server):
    code, _, err = run(capsys, "headers", vuln_server["url"], "--rate", "1000")
    assert code == 2  # no scope yet
    authorize(capsys)
    code, out, _ = run(capsys, "headers", vuln_server["url"], "--rate", "1000")
    payload = json.loads(out)
    assert code == 0 and payload["method"] == "headers"
    assert any(f["title"] == "Missing Content-Security-Policy header" for f in payload["findings"])


def test_unimplemented_commands_fail_honestly(capsys, home):
    code, _, err = run(capsys, "osint", "example.test")
    assert code == 1 and "not implemented" in err


def test_subdomains_on_ip_target_reports_nothing_found(capsys, home, vuln_server):
    authorize(capsys)
    code, out, _ = run(capsys, "subdomains", vuln_server["url"])
    assert code == 0 and "no in-scope subdomains" in out


def test_doctor_runs_real_checks(capsys, home):
    code, out, _ = run(capsys, "doctor")
    assert "[OK] Python >= 3.10" in out
    assert "SQLite database" in out and "Config directory writable" in out
    assert code in (0, 1)  # DNS may legitimately fail in an offline sandbox


def test_config_and_version_and_dorks_still_work(capsys, home):
    assert run(capsys, "--version")[1].strip() == "0.1.0"
    assert json.loads(run(capsys, "config", "--show")[1])["scope"]["include"] == []
    assert "site:example.test inurl:api" in run(capsys, "dorks", "example.test", "--category", "api")[1]
