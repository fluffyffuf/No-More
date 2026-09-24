"""Scope-enforcing, rate-limited HTTP client (standard library only).

Every request made by a NOMORE check goes through :class:`SafeClient`, which:

* refuses to contact a host that is outside the authorized scope,
* never follows a redirect that leaves the scope (it reports it instead),
* enforces a global requests-per-second limit,
* keeps an audit log of every request that was sent.
"""

from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

from .scope import ScopeEngine, ScopeError

REDIRECT_CODES = {301, 302, 303, 307, 308}
USER_AGENT = "NOMORE/0.1 (authorized security assessment)"


class FetchError(Exception):
    """A network-level failure (DNS, connection refused, timeout, TLS)."""


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes = b""
    redirect_chain: list[str] = field(default_factory=list)
    blocked_redirect: str | None = None

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class RateLimiter:
    """Simple global limiter: at most ``rate`` acquisitions per second."""

    def __init__(
        self,
        rate: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            if now < self._next:
                self._sleep(self._next - now)
                now = self._next
            self._next = now + self.interval


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable urllib's automatic redirects so scope can be checked on every hop."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


class SafeClient:
    def __init__(
        self,
        scope: ScopeEngine,
        rate_limit: float = 5,
        timeout: float = 10,
        max_redirects: int = 5,
        max_bytes: int = 1_000_000,
        verify_tls: bool = True,
        use_env_proxy: bool = False,
        limiter: RateLimiter | None = None,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.limiter = limiter or RateLimiter(rate_limit)
        self.audit: list[dict] = []

        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect(), urllib.request.HTTPSHandler(context=context)]
        if not use_env_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    # -- internals ---------------------------------------------------------
    def _send(self, url: str, headers: dict[str, str] | None) -> Response:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})}, method="GET")
        try:
            raw = self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:  # 3xx/4xx/5xx still carry a full response
            raw = error
        except (urllib.error.URLError, OSError, ValueError) as error:
            self._log(url, None)
            raise FetchError(f"{url}: {getattr(error, 'reason', error)}") from error
        try:
            body = raw.read(self.max_bytes)
            response = Response(url=url, status=raw.status if hasattr(raw, "status") else raw.code,
                                headers=list(raw.headers.items()), body=body)
        finally:
            raw.close()
        self._log(url, response.status)
        return response

    def _log(self, url: str, status: int | None) -> None:
        self.audit.append({"time": datetime.now(timezone.utc).isoformat(), "method": "GET", "url": url, "status": status})

    # -- public API --------------------------------------------------------
    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        """GET ``url``. Raises ScopeError if the *initial* URL is out of scope.

        Redirects are followed only while they stay in scope; a redirect that would
        leave scope stops the chain and is reported via ``Response.blocked_redirect``.
        """
        self.scope.require(url)
        chain: list[str] = []
        current = url
        while True:
            self.limiter.wait()
            response = self._send(current, headers)
            location = response.header("Location")
            if response.status in REDIRECT_CODES and location:
                target = urljoin(current, location)
                if urlparse(target).scheme not in ("http", "https") or not self.scope.is_target_in_scope(target):
                    response.blocked_redirect = target
                    response.redirect_chain = chain
                    return response
                if len(chain) >= self.max_redirects:
                    response.redirect_chain = chain
                    return response
                chain.append(current)
                current = target
                continue
            response.redirect_chain = chain
            return response


__all__ = ["FetchError", "RateLimiter", "Response", "SafeClient", "ScopeError"]
