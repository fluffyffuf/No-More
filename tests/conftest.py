import importlib.util
from pathlib import Path

import pytest

from nomore.scope import ScopeEngine

_FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app.py"


def _load_fixture_module():
    spec = importlib.util.spec_from_file_location("nomore_vuln_app", _FIXTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def vuln_server():
    """Run the intentionally vulnerable local app for the whole test session."""
    module = _load_fixture_module()
    server, _thread = module.start_server()
    handler = server.RequestHandlerClass
    port = server.server_address[1]
    yield {"url": f"http://127.0.0.1:{port}", "port": port, "seen": handler.seen}
    server.shutdown()
    server.server_close()


@pytest.fixture
def local_scope():
    return ScopeEngine(include=["127.0.0.1"], strict=True)


@pytest.fixture
def nomore_home(tmp_path, monkeypatch):
    """Isolate config and history so tests never touch the real ~/.config/nomore."""
    monkeypatch.setenv("NOMORE_HOME", str(tmp_path / "nomore-home"))
    return tmp_path / "nomore-home"
