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
