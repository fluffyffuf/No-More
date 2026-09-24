from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is installed for normal usage.
    yaml = None


DEFAULT_CONFIG: dict[str, Any] = {
    "target": "example.com",
    "scope": {"include": ["*.example.com"], "exclude": []},
    "testing": {"passive": True, "active": False, "rate_limit": 5},
    "profile": "standard",
}


@dataclass
class Config:
    target: str = "example.com"
    scope: dict[str, Any] = field(default_factory=lambda: {"include": ["*.example.com"], "exclude": []})
    testing: dict[str, Any] = field(default_factory=lambda: {"passive": True, "active": False, "rate_limit": 5})
    profile: str = "standard"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        merged = {**DEFAULT_CONFIG, **data}
        scope = {**DEFAULT_CONFIG["scope"], **merged.get("scope", {})}
        testing = {**DEFAULT_CONFIG["testing"], **merged.get("testing", {})}
        return cls(
            target=str(merged.get("target", "example.com")),
            scope=scope,
            testing=testing,
            profile=str(merged.get("profile", "standard")),
        )

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "Config":
        file_path = Path(path).expanduser()
        if not file_path.exists():
            return cls()
        if yaml is None:
            raise RuntimeError("PyYAML is required to load NOMORE configuration files.")
        with file_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scope": self.scope,
            "testing": self.testing,
            "profile": self.profile,
        }

    def save(self, path: str | os.PathLike[str]) -> None:
        file_path = Path(path).expanduser()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if yaml is None:
            raise RuntimeError("PyYAML is required to save NOMORE configuration files.")
        with file_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(self.to_dict(), handle, sort_keys=False)


def config_path() -> Path:
    return Path.home() / ".config" / "nomore" / "config.yaml"


def load_default_config() -> Config:
    path = config_path()
    if path.exists():
        return Config.from_file(path)
    return Config()
