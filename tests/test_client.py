import socket
from urllib.parse import urlparse

import pytest

from nomore.client import FetchError, RateLimiter, SafeClient
from nomore.scope import ScopeError


class FakeTime:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_rate_limiter_spaces_requests():
    fake = FakeTime()
    limiter = RateLimiter(2, clock=fake.clock, sleep=fake.sleep)  # 2 requests per second
    for _ in range(3):
        limiter.wait()
    assert fake.sleeps == [0.5, 0.5]


def test_rate_limiter_zero_means_unlimited():
    fake = FakeTime()
    limiter = RateLimiter(0, clock=fake.clock, sleep=fake.sleep)
    for _ in range(5):
        limiter.wait()
    assert fake.sleeps == []


def test_client_fetches_in_scope_url_and_logs_it(vuln_server, local_scope):
    client = SafeClient(local_scope, rate_limit=1000)
    response = client.get(vuln_server["url"] + "/api/v1/users")
    assert response.status == 200
    assert b"alice" in response.body
    assert client.audit[-1]["url"].endswith("/api/v1/users")
    assert client.audit[-1]["status"] == 200


def test_client_refuses_out_of_scope_url_without_sending(vuln_server):
    client = SafeClient(__import__("nomore.scope", fromlist=["ScopeEngine"]).ScopeEngine(["*.example.com"], strict=True))
    with pytest.raises(ScopeError):
        client.get(vuln_server["url"] + "/")
    assert client.audit == []


def test_client_does_not_follow_redirect_that_leaves_scope(vuln_server, local_scope):
    client = SafeClient(local_scope, rate_limit=1000)
    response = client.get(vuln_server["url"] + "/redirect-out")
    assert response.status == 302
    assert response.blocked_redirect == "http://evil.invalid/landing"
    assert all(urlparse(entry["url"]).hostname == "127.0.0.1" for entry in client.audit)


def test_client_follows_redirect_that_stays_in_scope(vuln_server, local_scope):
    client = SafeClient(local_scope, rate_limit=1000)
    response = client.get(vuln_server["url"] + "/redirect-in")
    assert response.status == 200
    assert response.url.endswith("/debug")
    assert response.redirect_chain == [vuln_server["url"] + "/redirect-in"]


def test_client_raises_fetch_error_when_nothing_is_listening(local_scope):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    client = SafeClient(local_scope, rate_limit=1000, timeout=2)
    with pytest.raises(FetchError):
        client.get(f"http://127.0.0.1:{port}/")


def test_response_header_helpers_are_case_insensitive_and_multi_valued():
    from nomore.client import Response

    response = Response("http://x", 200, [("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("Server", "s")])
    assert response.header("SERVER") == "s"
    assert response.header_all("Set-Cookie") == ["a=1", "b=2"]
    assert response.header("missing") is None
