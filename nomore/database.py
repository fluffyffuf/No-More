from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import db_path
from .models import Finding


class ScanDatabase:
    """Local SQLite storage for scan history and findings."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser() if path else db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:  # commit / rollback
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL UNIQUE,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    methods TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    errors TEXT NOT NULL
                )
                """
            )
            # Migrate databases created by earlier versions of the findings table.
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(findings)")}
            for column in ("scan_id", "fingerprint", "data"):
                if column not in existing:
                    connection.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")

    # -- legacy helpers ------------------------------------------------------
    def record_finding(self, target: str, title: str, severity: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO findings (target, title, severity, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (target, title, severity),
            )

    def count_findings(self, target: str | None = None) -> int:
        with self._connect() as connection:
            if target is None:
                row = connection.execute("SELECT COUNT(*) FROM findings").fetchone()
            else:
                row = connection.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,)).fetchone()
            return int(row[0]) if row else 0

    # -- scans ---------------------------------------------------------------
    def save_scan(self, result: dict) -> str:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO scans (scan_id, target, profile, methods, started_at, finished_at, summary, errors) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result["scan_id"],
                    result["target"],
                    result["profile"],
                    json.dumps(result["methods"]),
                    result["started_at"],
                    result["finished_at"],
                    json.dumps(result["summary"]),
                    json.dumps(result.get("errors", [])),
                ),
            )
            for item in result["findings"]:
                connection.execute(
                    "INSERT INTO findings (target, title, severity, scan_id, fingerprint, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (result["target"], item["title"], item["severity"], result["scan_id"], item["fingerprint"], json.dumps(item)),
                )
        return result["scan_id"]

    def _row_to_scan(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict:
        findings = [
            Finding.from_dict(json.loads(r["data"]))
            for r in connection.execute("SELECT data FROM findings WHERE scan_id = ? ORDER BY id", (row["scan_id"],))
            if r["data"]
        ]
        return {
            "scan_id": row["scan_id"],
            "target": row["target"],
            "profile": row["profile"],
            "methods": json.loads(row["methods"]),
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "summary": json.loads(row["summary"]),
            "errors": json.loads(row["errors"]),
            "findings": findings,
        }

    def get_scan(self, ref: str = "latest", target: str | None = None) -> dict | None:
        """Look up a scan by full id, unique id prefix, or ``latest`` (optionally per target)."""
        with self._connect() as connection:
            if ref == "latest":
                query, params = "SELECT * FROM scans", []
                if target:
                    query, params = query + " WHERE target = ?", [target]
                row = connection.execute(query + " ORDER BY id DESC LIMIT 1", params).fetchone()
            else:
                rows = connection.execute("SELECT * FROM scans WHERE scan_id LIKE ? ORDER BY id DESC", (ref + "%",)).fetchall()
                if len(rows) > 1:
                    exact = [r for r in rows if r["scan_id"] == ref]
                    if not exact:
                        raise LookupError(f"scan id prefix '{ref}' is ambiguous")
                    rows = exact
                row = rows[0] if rows else None
            return self._row_to_scan(connection, row) if row else None

    def list_scans(self, target: str | None = None, limit: int = 20) -> list[dict]:
        with self._connect() as connection:
            query, params = "SELECT * FROM scans", []
            if target:
                query, params = query + " WHERE target = ?", [target]
            rows = connection.execute(query + " ORDER BY id DESC LIMIT ?", params + [limit]).fetchall()
            return [
                {
                    "scan_id": r["scan_id"],
                    "target": r["target"],
                    "profile": r["profile"],
                    "started_at": r["started_at"],
                    "summary": json.loads(r["summary"]),
                }
                for r in rows
            ]

    def diff_scans(self, old_ref: str, new_ref: str) -> dict:
        old, new = self.get_scan(old_ref), self.get_scan(new_ref)
        if old is None or new is None:
            raise LookupError("one of the scans was not found")
        old_by_fp = {f.fingerprint(): f for f in old["findings"]}
        new_by_fp = {f.fingerprint(): f for f in new["findings"]}
        return {
            "old": old["scan_id"],
            "new": new["scan_id"],
            "old_errors": len(old["errors"]),
            "new_errors": len(new["errors"]),
            "new_findings": [new_by_fp[k] for k in new_by_fp if k not in old_by_fp],
            "fixed_findings": [old_by_fp[k] for k in old_by_fp if k not in new_by_fp],
            "unchanged_findings": [new_by_fp[k] for k in new_by_fp if k in old_by_fp],
        }
