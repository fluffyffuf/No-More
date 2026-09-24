from __future__ import annotations

import fnmatch
from ipaddress import ip_address
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when something outside the authorized scope is about to be touched."""


def host_from_target(target: str) -> str:
    """Extract the lower-cased hostname from a bare host, host:port, or full URL."""
    value = target.strip()
    if "://" not in value:
        value = "//" + value
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


class ScopeEngine:
    """Small, safety-first scope evaluator for authorized targets.

    With ``strict=True`` an empty include list authorizes nothing (instead of everything).
    """

    def __init__(self, include: list[str] | None = None, exclude: list[str] | None = None, strict: bool = False):
        self.include = [self._normalize_pattern(p) for p in (include or [])]
        self.exclude = [self._normalize_pattern(p) for p in (exclude or [])]
        self.strict = strict

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        value = pattern.strip().lower()
        if value.startswith("*"):
            return value
        return value.lstrip(".")

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        value = hostname.strip().lower()
        if value.startswith("[") and "]" in value:
            value = value[1 : value.index("]")]  # bracketed IPv6, optionally with :port
        elif value.count(":") == 1:
            value = value.split(":")[0]  # host:port (a bare IPv6 has several colons)
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
            return not self.strict

        return any(self.matches_pattern(p, normalized) for p in self.include)

    def is_target_in_scope(self, target: str) -> bool:
        """Scope check for a host, host:port, or URL."""
        return self.is_in_scope(host_from_target(target))

    def require(self, target: str) -> None:
        if not self.is_target_in_scope(target):
            raise ScopeError(f"{target} is out of scope")
