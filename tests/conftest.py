import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The tests drive real widgets; without this they need a display server.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub_vol.py")


@pytest.fixture(scope="session")
def qapp():
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def stub_vol(monkeypatch):
    """Point the runner at a stub that emits the awkward output shapes vol3 can."""
    import core.vol_runner as vol_runner
    monkeypatch.setattr(vol_runner, "find_vol3_command", lambda: [sys.executable, STUB])
    return STUB


@pytest.fixture(autouse=True)
def _isolated_config(monkeypatch, tmp_path_factory):
    """
    Every test gets its own config directory and a fresh run gate.

    Without this, any test that opens a window writes settings and the
    recent-case list into the developer's real ~/.config/dumpscope, and one
    test raising the parallel-run limit leaks it into the next.
    """
    from core import settings
    from core.vol_runner import RUN_GATE

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("config")))
    settings._cache = None
    RUN_GATE.set_limit(1)
    yield
    settings._cache = None
    RUN_GATE.set_limit(1)
