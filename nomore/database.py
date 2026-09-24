from __future__ import annotations

import sqlite3
from pathlib import Path


class ScanDatabase:
    """Local SQLite storage for scan history and findings."""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path or (Path.home() / ".config" / "nomore" / "history.db")).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.path) as connection:
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

    def record_finding(self, target: str, title: str, severity: str) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT INTO findings (target, title, severity, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (target, title, severity),
            )

    def count_findings(self, target: str | None = None) -> int:
        with sqlite3.connect(self.path) as connection:
            if target is None:
                row = connection.execute("SELECT COUNT(*) FROM findings").fetchone()
                return int(row[0]) if row else 0
            row = connection.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,)).fetchone()
            return int(row[0]) if row else 0
