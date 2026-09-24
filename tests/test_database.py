import sqlite3
import uuid

import pytest

from nomore.database import ScanDatabase
from nomore.models import Finding, Severity


def make_result(target="example.test", findings=(), errors=()):
    return {
        "scan_id": str(uuid.uuid4()),
        "target": target,
        "profile": "standard",
        "methods": ["headers"],
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:05+00:00",
        "summary": {"total_findings": len(findings), "severity_counts": {}},
        "errors": list(errors),
        "findings": [f.to_dict() for f in findings],
    }


def finding(title, severity=Severity.LOW, asset="https://example.test", evidence=("e",)):
    return Finding(title=title, severity=severity, affected_asset=asset, evidence=list(evidence))


@pytest.fixture
def db(tmp_path):
    return ScanDatabase(tmp_path / "history.db")


def test_save_and_load_scan_round_trips_findings(db):
    result = make_result(findings=[finding("A", Severity.HIGH), finding("B")])
    db.save_scan(result)
    loaded = db.get_scan(result["scan_id"])
    assert loaded["target"] == "example.test"
    assert [f.title for f in loaded["findings"]] == ["A", "B"]
    assert loaded["findings"][0].severity == Severity.HIGH
    assert loaded["findings"][0].evidence == ["e"]


def test_latest_and_prefix_lookup(db):
    first, second = make_result(), make_result(target="other.test")
    db.save_scan(first)
    db.save_scan(second)
    assert db.get_scan("latest")["scan_id"] == second["scan_id"]
    assert db.get_scan("latest", target="example.test")["scan_id"] == first["scan_id"]
    assert db.get_scan(first["scan_id"][:8])["scan_id"] == first["scan_id"]
    assert db.get_scan("does-not-exist") is None


def test_ambiguous_prefix_is_an_error(db):
    a, b = make_result(), make_result()
    a["scan_id"], b["scan_id"] = "abc-1", "abc-2"
    db.save_scan(a)
    db.save_scan(b)
    with pytest.raises(LookupError):
        db.get_scan("abc")


def test_list_scans_newest_first_with_target_filter(db):
    for target in ("a.test", "b.test", "a.test"):
        db.save_scan(make_result(target=target))
    assert [s["target"] for s in db.list_scans()] == ["a.test", "b.test", "a.test"]
    assert len(db.list_scans(target="a.test")) == 2
    assert len(db.list_scans(limit=1)) == 1


def test_diff_reports_new_fixed_and_unchanged(db):
    old = make_result(findings=[finding("Stays"), finding("Gets fixed")])
    new = make_result(findings=[finding("Stays"), finding("Brand new", Severity.HIGH)])
    db.save_scan(old)
    db.save_scan(new)
    diff = db.diff_scans(old["scan_id"], new["scan_id"])
    assert [f.title for f in diff["new_findings"]] == ["Brand new"]
    assert [f.title for f in diff["fixed_findings"]] == ["Gets fixed"]
    assert [f.title for f in diff["unchanged_findings"]] == ["Stays"]


def test_diff_reports_scan_errors_so_incomplete_scans_can_be_flagged(db):
    old = make_result(findings=[finding("A")])
    new = make_result(errors=[{"method": "headers", "error": "FetchError: down"}])
    db.save_scan(old)
    db.save_scan(new)
    diff = db.diff_scans(old["scan_id"], new["scan_id"])
    assert (diff["old_errors"], diff["new_errors"]) == (0, 1)


def test_diff_unknown_scan_raises(db):
    with pytest.raises(LookupError):
        db.diff_scans("nope", "nada")


def test_same_finding_on_different_urls_has_different_fingerprints():
    a = Finding(title="CORS", affected_asset="x", affected_url="https://x/a")
    b = Finding(title="CORS", affected_asset="x", affected_url="https://x/b")
    assert a.fingerprint() != b.fingerprint()


def test_legacy_database_is_migrated_in_place(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, "
            "title TEXT NOT NULL, severity TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        connection.execute("INSERT INTO findings (target, title, severity) VALUES ('t', 'old finding', 'LOW')")
    db = ScanDatabase(path)
    assert db.count_findings() == 1  # old rows survive
    db.save_scan(make_result(findings=[finding("A")]))  # new columns exist
    assert db.count_findings() == 2
    db.record_finding("t", "legacy api still works", "INFO")
    assert db.count_findings("t") == 2
