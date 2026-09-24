from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from .checks import CHECKS, CheckContext
from .client import SafeClient
from .models import SEVERITY_ORDER, Finding
from .scope import ScopeEngine


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share a fingerprint, keeping the first and combining evidence."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint()
        if key not in merged:
            merged[key] = finding
            continue
        existing = merged[key]
        existing.evidence.extend(item for item in finding.evidence if item not in existing.evidence)
        if finding.severity.rank > existing.severity.rank:
            existing.severity = finding.severity
    return list(merged.values())


class ScanEngine:
    """Safety-first orchestration layer for NOMORE reconnaissance and assessment.

    The engine refuses to run unless the target is inside the authorized scope, and all
    network traffic goes through a scope-enforcing, rate-limited client.
    """

    METHOD_CATALOG = {
        "passive": ["dns", "certs", "headers"],
        "recon": ["dns", "certs", "subdomains", "technologies", "headers"],
        "web": ["crawl", "technologies", "headers", "cookies", "cors", "findings"],
        "api": ["api", "headers", "cors", "tls", "findings"],
        "standard": ["dns", "certs", "subdomains", "crawl", "technologies", "headers", "tls", "api", "findings"],
        "deep": ["dns", "certs", "subdomains", "crawl", "technologies", "headers", "tls", "cookies", "cors", "api", "findings"],
        "ci": ["dns", "headers", "tls", "api", "findings"],
        "bug-bounty": ["dns", "subdomains", "crawl", "technologies", "headers", "cookies", "cors", "api", "findings"],
        "all": ["dns", "certs", "subdomains", "crawl", "technologies", "headers", "tls", "cookies", "cors", "api", "findings"],
    }

    def __init__(
        self,
        scope: ScopeEngine,
        client: SafeClient | None = None,
        active: bool = False,
        verify_tls: bool = True,
        timeout: float = 10,
        ct_fetcher: Callable[[str], list[dict]] | None = None,
        tls_prober: Callable[..., dict] | None = None,
    ) -> None:
        self.scope = scope
        self.client = client
        self.active = active
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.ct_fetcher = ct_fetcher
        self.tls_prober = tls_prober

    @classmethod
    def methods_for(cls, method: str) -> list[str]:
        name = (method or "standard").lower()
        if name in cls.METHOD_CATALOG:
            return list(cls.METHOD_CATALOG[name])
        if name in CHECKS:
            return [name]
        raise ValueError(f"unknown scan method: {method}")

    def run(self, target: str, method: str = "standard", profile: str = "standard", rate_limit: int = 5, concurrency: int = 5) -> dict:
        """Run a scan. ``concurrency`` is reserved: checks currently run sequentially."""
        self.scope.require(target)  # raises ScopeError before any network traffic
        methods = self.methods_for(method)
        client = self.client or SafeClient(self.scope, rate_limit=rate_limit, timeout=self.timeout, verify_tls=self.verify_tls)
        ctx = CheckContext(
            target=target,
            scope=self.scope,
            client=client,
            active=self.active,
            timeout=self.timeout,
            verify_tls=self.verify_tls,
            ct_fetcher=self.ct_fetcher,
            tls_prober=self.tls_prober,
        )

        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[dict] = []
        for name in methods:
            try:
                findings.extend(CHECKS[name](ctx))
            except Exception as error:  # one failing check must not abort the whole scan
                errors.append({"method": name, "error": f"{type(error).__name__}: {error}"})

        findings = dedupe_findings(findings)
        findings.sort(key=lambda item: item.severity.rank, reverse=True)
        counts = {label: 0 for label in SEVERITY_ORDER}
        for item in findings:
            counts[str(item.severity)] += 1

        assets = [{"host": ctx.host, "type": "target"}]
        assets += [{"host": host, "type": "subdomain"} for host in sorted(ctx.discovered_hosts)]
        return {
            "scan_id": str(uuid4()),
            "target": target,
            "profile": profile,
            "methods": methods,
            "started_at": started.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "findings": [finding.to_dict() for finding in findings],
            "errors": errors,
            "requests_made": len(client.audit),
            "summary": {
                "target": target,
                "total_findings": len(findings),
                "severity_counts": counts,
                "profile": profile,
                "rate_limit": rate_limit,
                "concurrency": concurrency,
            },
            "assets": assets,
            "technologies": sorted(ctx.technologies),
        }
