from __future__ import annotations

import fnmatch
from ipaddress import ip_address


class ScopeEngine:
    """Small, safety-first scope evaluator for authorized targets."""

    def __init__(self, include: list[str] | None = None, exclude: list[str] | None = None):
        self.include = [self._normalize_pattern(p) for p in (include or [])]
        self.exclude = [self._normalize_pattern(p) for p in (exclude or [])]

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        value = pattern.strip().lower()
        if value.startswith("*"):
            return value
        return value.lstrip(".")

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        value = hostname.strip().lower().split(":")[0]
        if value.startswith("[") and "]" in value:
            value = value[1 : value.index("]")]
        return value.rstrip(".")

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ip_address(value)
            return True
        except ValueError:
            return False

    def matches_pattern(self, pattern: str, value: str) -> bool:
        normalized = self._normalize_hostname(value)
        pattern_text = self._normalize_pattern(pattern)

        if pattern_text.startswith("*."):
            suffix = pattern_text[2:]
            return normalized == suffix or normalized.endswith("." + suffix)
        if pattern_text.startswith("*"):
            return fnmatch.fnmatch(normalized, pattern_text)
        if self._looks_like_ip(pattern_text) and self._looks_like_ip(normalized):
            return normalized == pattern_text
        return normalized == pattern_text or normalized.endswith("." + pattern_text)

    def is_in_scope(self, hostname: str) -> bool:
        normalized = self._normalize_hostname(hostname)
        if not normalized:
            return False

        if self.exclude and any(self.matches_pattern(p, normalized) for p in self.exclude):
            return False

        if not self.include:
            return True

        return any(self.matches_pattern(p, normalized) for p in self.include)
