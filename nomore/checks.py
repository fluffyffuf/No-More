"""Assessment checks.

Each check is a function ``check(ctx) -> list[Finding]`` registered in ``CHECKS``.
Checks are passive by default: they read responses, headers, certificates, and public
certificate-transparency data. Anything that probes paths the target did not link to
(such as API documentation URLs) only runs when ``ctx.active`` is true.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from ipaddress import ip_address
from typing import Callable
from urllib.parse import quote, urldefrag, urljoin, urlparse

from .client import USER_AGENT, FetchError, Response, SafeClient
from .models import Finding, Severity
from .scope import ScopeEngine, ScopeError, host_from_target

Check = Callable[["CheckContext"], list[Finding]]

# Links that may change state when requested with GET are never followed by the crawler.
UNSAFE_LINK = re.compile(r"logout|signout|sign-out|log-out|delete|remove|unsubscribe", re.IGNORECASE)
API_PATH = re.compile(r"(^|/)(api|graphql|swagger|openapi|api-docs)(/|\.|$)", re.IGNORECASE)
SESSION_COOKIE = re.compile(r"sess|auth|token|sid|jwt", re.IGNORECASE)
CORS_PROBE_ORIGIN = "https://nomore-cors-probe.invalid"
API_DOC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs"]


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------
class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[tuple[str, str]] = []
        self.generator: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {key: value or "" for key, value in attrs}
        if tag == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag == "form":
            self.forms.append((data.get("method", "get").upper(), data.get("action", "")))
        elif tag == "meta" and data.get("name", "").lower() == "generator" and data.get("content"):
            self.generator = data["content"]


@dataclass
class CheckContext:
    target: str
    scope: ScopeEngine
    client: SafeClient
    active: bool = False
    timeout: float = 10
    verify_tls: bool = True
    max_pages: int = 15
    ct_fetcher: Callable[[str], list[dict]] | None = None
    tls_prober: Callable[..., dict] | None = None

    technologies: set[str] = field(default_factory=set)
    discovered_hosts: set[str] = field(default_factory=set)
    pages: dict[str, Response] = field(default_factory=dict)
    _home: Response | None = None
    _crawl: list[str] | None = None
    _forms: list[str] = field(default_factory=list)
    _tls: dict | None = None

    def __post_init__(self) -> None:
        self.base_url = self.target if "://" in self.target else f"https://{self.target}"
        parsed = urlparse(self.base_url)
        self.scheme = parsed.scheme
        self.host = host_from_target(self.base_url)
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

    def home(self) -> Response:
        if self._home is None:
            self._home = self.client.get(self.base_url)
            self.pages[self._home.url] = self._home
        return self._home

    def crawl(self) -> list[str]:
        """Breadth-first, same-host, in-scope crawl of GET links (bounded by ``max_pages``)."""
        if self._crawl is not None:
            return self._crawl
        home = self.home()
        order = [home.url]
        seen = {home.url}
        queue = [home]
        while queue:
            page = queue.pop(0)
            if "html" not in (page.header("content-type") or "").lower():
                continue
            parser = _PageParser()
            parser.feed(page.text)
            if parser.generator:
                self.technologies.add(parser.generator)
            for method, action in parser.forms:
                self._forms.append(f"form {method} {urlparse(urljoin(page.url, action)).path or '/'}")
            for link in parser.links:
                absolute = urldefrag(urljoin(page.url, link))[0]
                if urlparse(absolute).scheme not in ("http", "https") or UNSAFE_LINK.search(absolute):
                    continue
                if absolute in seen or host_from_target(absolute) != self.host:
                    continue
                if not self.scope.is_target_in_scope(absolute) or len(order) >= self.max_pages:
                    continue
                seen.add(absolute)
                order.append(absolute)
                try:
                    response = self.client.get(absolute)
                except (FetchError, ScopeError):
                    continue
                self.pages[response.url] = response
                queue.append(response)
        self._crawl = order
        return order

    def tls_info(self) -> dict:
        if self._tls is None:
            prober = self.tls_prober or probe_tls
            self._tls = prober(self.host, self.port, self.timeout, self.verify_tls)
        return self._tls

    def finding(
        self,
        title: str,
        severity: Severity,
        confidence: str,
        evidence: list[str],
        remediation: str,
        *,
        description: str = "",
        url: str = "",
        parameter: str = "",
        method: str = "",
        references: list[str] | None = None,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            affected_asset=self.base_url,
            affected_url=url,
            parameter=parameter,
            evidence=evidence,
            description=description,
            remediation=remediation,
            references=references or [],
            detection_method=method,
            source="nomore",
        )


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------
def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def check_dns(ctx: CheckContext) -> list[Finding]:
    if _is_ip(ctx.host):
        return []
    try:
        infos = socket.getaddrinfo(ctx.host, None)
    except socket.gaierror as error:
        raise FetchError(f"DNS resolution failed for {ctx.host}: {error}") from error
    addresses = sorted({info[4][0] for info in infos})
    evidence = [f"{ctx.host} resolves to {address}" for address in addresses]
    private = [a for a in addresses if ip_address(a.split("%")[0]).is_private]
    if private:
        evidence.append("private/loopback addresses: " + ", ".join(private))
    return [
        ctx.finding(
            "DNS resolution reviewed",
            Severity.INFO,
            "high",
            evidence,
            "Keep DNS records tightly scoped and monitor for unexpected changes.",
            description="The target hostname was resolved to confirm which addresses serve it.",
            method="dns-resolution",
        )
    ]


# ---------------------------------------------------------------------------
# tls / certs
# ---------------------------------------------------------------------------
def probe_tls(host: str, port: int, timeout: float = 10, verify: bool = True) -> dict:
    """Open one TLS connection and report protocol, cipher, certificate, and verification result."""
    info: dict = {"version": None, "cipher": None, "cert": None, "verify_error": None}

    def handshake(context: ssl.SSLContext) -> None:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                info["version"] = tls.version()
                cipher = tls.cipher()
                info["cipher"] = cipher[0] if cipher else None
                info["cert"] = tls.getpeercert() or None

    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        handshake(ssl.create_default_context() if verify else unverified)
    except ssl.SSLCertVerificationError as error:
        info["verify_error"] = error.verify_message or str(error)
        try:
            handshake(unverified)  # still gather protocol details
        except (OSError, ssl.SSLError):
            pass
    except (OSError, ssl.SSLError) as error:
        raise FetchError(f"TLS connection to {host}:{port} failed: {error}") from error
    return info


def summarize_certificate(cert: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    issuer = {key: value for rdn in cert.get("issuer", ()) for key, value in rdn}
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    return {
        "expires": expires,
        "days_left": (expires - now).days,
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "unknown",
        "sans": sans,
    }


def check_tls(ctx: CheckContext) -> list[Finding]:
    if ctx.scheme != "https":
        return [
            ctx.finding(
                "TLS not evaluated: target uses plain HTTP",
                Severity.INFO,
                "high",
                [f"Target URL {ctx.base_url} does not use HTTPS"],
                "Serve the site over HTTPS and redirect all HTTP traffic to it.",
                method="tls-scheme",
            )
        ]
    info = ctx.tls_info()
    findings: list[Finding] = []
    if info.get("verify_error"):
        findings.append(
            ctx.finding(
                "TLS certificate failed verification",
                Severity.MEDIUM,
                "high",
                [str(info["verify_error"])],
                "Install a valid certificate from a trusted CA that matches the hostname.",
                description="Clients that validate certificates will reject this connection.",
                method="tls-handshake",
            )
        )
    version = info.get("version")
    if version:
        weak = version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
        findings.append(
            ctx.finding(
                "Deprecated TLS protocol negotiated" if weak else "TLS protocol negotiated",
                Severity.MEDIUM if weak else Severity.INFO,
                "high",
                [f"protocol: {version}", f"cipher: {info.get('cipher')}"],
                "Disable TLS versions below 1.2 and prefer TLS 1.3.",
                method="tls-handshake",
            )
        )
    return findings


def check_certs(ctx: CheckContext) -> list[Finding]:
    if ctx.scheme != "https":
        return []
    cert = ctx.tls_info().get("cert")
    if not cert:
        return []
    summary = summarize_certificate(cert)
    days = summary["days_left"]
    evidence = [
        f"issuer: {summary['issuer']}",
        f"expires: {summary['expires'].date().isoformat()} ({days} days left)",
        f"subject alternative names: {len(summary['sans'])}",
    ]
    findings = [
        ctx.finding(
            "Certificate inventory reviewed",
            Severity.INFO,
            "high",
            evidence,
            "Monitor certificate rotations and expiry windows for all public assets.",
            method="tls-certificate",
        )
    ]
    if days < 30:
        expired = days < 0
        findings.append(
            ctx.finding(
                "TLS certificate expired" if expired else "TLS certificate expires soon",
                Severity.HIGH if expired else (Severity.MEDIUM if days <= 14 else Severity.LOW),
                "high",
                evidence[:2],
                "Renew the certificate and automate renewal (for example with ACME).",
                method="tls-certificate",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# subdomains (passive: certificate transparency)
# ---------------------------------------------------------------------------
def crtsh_fetch(domain: str, timeout: float = 20) -> list[dict]:
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as handle:
            return json.load(handle)
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise FetchError(f"certificate transparency lookup failed: {error}") from error


def parse_ct_names(records: list[dict], domain: str, scope: ScopeEngine) -> tuple[list[str], int]:
    """Return (in-scope subdomains, number dropped because they were out of scope)."""
    domain = domain.lower().rstrip(".")
    names: set[str] = set()
    for record in records:
        for raw in str(record.get("name_value", "")).splitlines() + [str(record.get("common_name", ""))]:
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name and name != domain and name.endswith("." + domain) and re.fullmatch(r"[a-z0-9.-]+", name):
                names.add(name)
    in_scope = sorted(name for name in names if scope.is_in_scope(name))
    return in_scope, len(names) - len(in_scope)


def check_subdomains(ctx: CheckContext) -> list[Finding]:
    if _is_ip(ctx.host):
        return []
    fetcher = ctx.ct_fetcher or crtsh_fetch
    names, dropped = parse_ct_names(fetcher(ctx.host), ctx.host, ctx.scope)
    if not names:
        return []
    ctx.discovered_hosts.update(names)
    evidence = names[:50] + ([f"... and {len(names) - 50} more"] if len(names) > 50 else [])
    if dropped:
        evidence.append(f"{dropped} candidate(s) excluded because they are out of scope")
    return [
        ctx.finding(
            "Subdomain candidates identified",
            Severity.INFO,
            "medium",
            evidence,
            "Review each host for ownership, authentication boundaries, and exposure.",
            description="Names were taken from public certificate-transparency logs; no host was contacted.",
            method="certificate-transparency",
        )
    ]


# ---------------------------------------------------------------------------
# headers
# ---------------------------------------------------------------------------
HEADER_RULES = [
    ("content-security-policy", "Missing Content-Security-Policy header", Severity.LOW,
     "Add a Content-Security-Policy that restricts script, frame, and object sources."),
    ("x-content-type-options", "Missing X-Content-Type-Options header", Severity.LOW,
     "Send 'X-Content-Type-Options: nosniff'."),
    ("referrer-policy", "Missing Referrer-Policy header", Severity.INFO,
     "Send a Referrer-Policy such as 'strict-origin-when-cross-origin'."),
    ("permissions-policy", "Missing Permissions-Policy header", Severity.INFO,
     "Send a Permissions-Policy that disables browser features the site does not use."),
]


def check_headers(ctx: CheckContext) -> list[Finding]:
    home = ctx.home()
    where = f"{home.url} (HTTP {home.status})"
    findings: list[Finding] = []

    if home.blocked_redirect:
        findings.append(
            ctx.finding(
                "Redirect to out-of-scope host not followed",
                Severity.INFO,
                "high",
                [f"{home.url} redirects to {home.blocked_redirect}", "NOMORE did not contact the redirect target"],
                "Confirm whether the redirect destination should be added to the authorized scope.",
                method="redirect-scope-check",
            )
        )

    for header, title, severity, fix in HEADER_RULES:
        if home.header(header) is None:
            findings.append(
                ctx.finding(title, severity, "high", [f"'{header}' absent in response from {where}"], fix,
                            url=home.url, parameter=header, method="http-header-check"))

    csp = (home.header("content-security-policy") or "").lower()
    if home.header("x-frame-options") is None and "frame-ancestors" not in csp:
        findings.append(
            ctx.finding("Clickjacking protection missing", Severity.LOW, "high",
                        [f"neither X-Frame-Options nor CSP frame-ancestors present in {where}"],
                        "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
                        url=home.url, parameter="x-frame-options", method="http-header-check"))

    if home.url.startswith("https://") and home.header("strict-transport-security") is None:
        findings.append(
            ctx.finding("Missing HSTS header", Severity.LOW, "high",
                        [f"'strict-transport-security' absent in response from {where}"],
                        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                        url=home.url, parameter="strict-transport-security", method="http-header-check"))

    server = home.header("server") or ""
    if re.search(r"\d+\.\d+", server):
        findings.append(
            ctx.finding("Server version disclosed", Severity.LOW, "high", [f"Server: {server}"],
                        "Remove version details from the Server header.",
                        url=home.url, parameter="server", method="http-header-check"))
    powered = home.header("x-powered-by")
    if powered:
        findings.append(
            ctx.finding("Technology disclosed via X-Powered-By", Severity.LOW, "high", [f"X-Powered-By: {powered}"],
                        "Remove the X-Powered-By header.",
                        url=home.url, parameter="x-powered-by", method="http-header-check"))
    return findings


# ---------------------------------------------------------------------------
# cookies
# ---------------------------------------------------------------------------
def parse_set_cookie(raw: str) -> dict:
    parts = [part.strip() for part in raw.split(";")]
    name, _, _value = parts[0].partition("=")
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip()
    return {"name": name.strip(), "attributes": attributes}


def check_cookies(ctx: CheckContext) -> list[Finding]:
    ctx.home()
    responses = list(ctx.pages.values())
    findings: list[Finding] = []
    seen: set[str] = set()
    for response in responses:
        for raw in response.header_all("set-cookie"):
            cookie = parse_set_cookie(raw)
            name, attrs = cookie["name"], cookie["attributes"]
            if not name or name in seen:
                continue
            seen.add(name)
            problems: list[str] = []
            severity = Severity.LOW
            if "httponly" not in attrs:
                problems.append("HttpOnly flag missing")
                if SESSION_COOKIE.search(name):
                    severity = Severity.MEDIUM
            if "secure" not in attrs and response.url.startswith("https://"):
                problems.append("Secure flag missing")
            if "samesite" not in attrs:
                problems.append("SameSite attribute not set")
            elif attrs["samesite"].lower() == "none" and "secure" not in attrs:
                problems.append("SameSite=None without Secure")
            if problems:
                findings.append(
                    ctx.finding("Cookie missing security attributes", severity, "high",
                                [f"cookie '{name}' set by {response.url}"] + problems,
                                "Set Secure, HttpOnly, and an explicit SameSite attribute on cookies.",
                                url=response.url, parameter=name, method="cookie-attribute-check"))
    return findings


# ---------------------------------------------------------------------------
# cors
# ---------------------------------------------------------------------------
def check_cors(ctx: CheckContext) -> list[Finding]:
    urls = [ctx.base_url]
    if ctx._crawl:  # only reuse crawl results that already exist; do not trigger a crawl
        urls += [u for u in ctx._crawl if API_PATH.search(urlparse(u).path)][:2]
    findings: list[Finding] = []
    for url in urls:
        response = ctx.client.get(url, headers={"Origin": CORS_PROBE_ORIGIN})
        allow = response.header("access-control-allow-origin")
        credentials = (response.header("access-control-allow-credentials") or "").lower() == "true"
        if allow == CORS_PROBE_ORIGIN:
            findings.append(
                ctx.finding("CORS policy reflects arbitrary origins",
                            Severity.HIGH if credentials else Severity.MEDIUM, "high",
                            [f"Origin: {CORS_PROBE_ORIGIN} was echoed in Access-Control-Allow-Origin",
                             f"Access-Control-Allow-Credentials: {credentials}"],
                            "Allow only an explicit list of trusted origins; never combine reflection with credentials.",
                            description="A page on any origin could read responses from this endpoint.",
                            url=response.url, parameter="access-control-allow-origin", method="cors-origin-probe"))
        elif allow == "null" and credentials:
            findings.append(
                ctx.finding("CORS policy trusts the 'null' origin with credentials", Severity.MEDIUM, "high",
                            ["Access-Control-Allow-Origin: null", "Access-Control-Allow-Credentials: true"],
                            "Do not allow the 'null' origin when credentials are enabled.",
                            url=response.url, parameter="access-control-allow-origin", method="cors-origin-probe"))
        elif allow == "*":
            findings.append(
                ctx.finding("CORS policy allows any origin (wildcard)", Severity.INFO, "high",
                            ["Access-Control-Allow-Origin: *"],
                            "Confirm the endpoint serves only public data.",
                            url=response.url, parameter="access-control-allow-origin", method="cors-origin-probe"))
    return findings


# ---------------------------------------------------------------------------
# crawl / technologies / api
# ---------------------------------------------------------------------------
def check_crawl(ctx: CheckContext) -> list[Finding]:
    urls = ctx.crawl()
    paths = [(urlparse(u).path or "/") + (f"?{urlparse(u).query}" if urlparse(u).query else "") for u in urls]
    evidence = paths[:25] + ([f"... and {len(paths) - 25} more"] if len(paths) > 25 else []) + ctx._forms[:10]
    return [
        ctx.finding(
            "Crawl inventory created",
            Severity.INFO,
            "medium",
            evidence,
            "Review discovered routes and parameters for authentication and exposure.",
            description=f"{len(urls)} in-scope page(s) discovered by following GET links. Forms were listed, never submitted.",
            method="crawl",
        )
    ]


COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java servlet container", "connect.sid": "Express (Node.js)",
               "csrftoken": "Django", "laravel_session": "Laravel", "asp.net_sessionid": "ASP.NET"}


def check_technologies(ctx: CheckContext) -> list[Finding]:
    home = ctx.home()
    evidence: list[str] = []
    for header in ("server", "x-powered-by", "x-generator", "via"):
        value = home.header(header)
        if value:
            evidence.append(f"{header}: {value}")
            ctx.technologies.add(value.split("/")[0].strip().lower())
    if home.header("cf-ray"):
        evidence.append("cf-ray header present (Cloudflare)")
        ctx.technologies.add("cloudflare")
    for raw in home.header_all("set-cookie"):
        name = parse_set_cookie(raw)["name"].lower()
        if name in COOKIE_TECH:
            evidence.append(f"cookie '{name}' suggests {COOKIE_TECH[name]}")
            ctx.technologies.add(COOKIE_TECH[name])
    if ctx._crawl is not None or "html" in (home.header("content-type") or "").lower():
        parser = _PageParser()
        parser.feed(home.text)
        if parser.generator:
            evidence.append(f"meta generator: {parser.generator}")
            ctx.technologies.add(parser.generator)
    if not evidence:
        return []
    return [
        ctx.finding("Technology profile identified", Severity.INFO, "medium", evidence,
                    "Use fingerprints to prioritise patching and hardening.",
                    description="Technologies were inferred from response headers, cookies, and page metadata.",
                    method="technology-fingerprint")
    ]


def check_api(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    api_urls = [u for u in ctx.crawl() if API_PATH.search(urlparse(u).path)]
    if api_urls:
        findings.append(
            ctx.finding("API surface identified", Severity.INFO, "high",
                        [urlparse(u).path or "/" for u in api_urls[:25]],
                        "Review API authentication, versioning, and documentation exposure.",
                        description="API-looking routes were linked from the crawled pages.",
                        method="crawl-api-routes"))
    if ctx.active:
        origin = f"{urlparse(ctx.base_url).scheme}://{urlparse(ctx.base_url).netloc}"
        for path in API_DOC_PATHS:
            try:
                response = ctx.client.get(origin + path)
            except (FetchError, ScopeError):
                continue
            head = response.text[:2000].lower()
            if response.status == 200 and response.text.lstrip().startswith("{") and ("openapi" in head or "swagger" in head):
                findings.append(
                    ctx.finding("API documentation publicly exposed", Severity.LOW, "high",
                                [f"{response.url} returned an OpenAPI/Swagger document"],
                                "Restrict API documentation to authenticated users or internal networks.",
                                url=response.url, method="active-api-doc-probe"))
    return findings


def check_findings(ctx: CheckContext) -> list[Finding]:
    """Correlation step. De-duplication happens in the engine, so nothing to add here."""
    return []


CHECKS: dict[str, Check] = {
    "dns": check_dns,
    "certs": check_certs,
    "tls": check_tls,
    "subdomains": check_subdomains,
    "crawl": check_crawl,
    "technologies": check_technologies,
    "headers": check_headers,
    "cookies": check_cookies,
    "cors": check_cors,
    "api": check_api,
    "findings": check_findings,
}
