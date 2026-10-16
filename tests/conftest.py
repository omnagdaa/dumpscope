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
def timeline(qapp):
    """A timeline view showing every fixture plugin's events (the compromised host)."""
    from PyQt6.QtWidgets import QApplication
    from tests.vol_fixtures import all_payloads
    from ui.timeline_view import TimelineView
    view = TimelineView()
    view.resize(1200, 700)
    view.show()
    view.set_payloads(all_payloads(), missing=["windows.netscan.NetScan"])
    QApplication.processEvents()
    yield view
    view.close()


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
    _destroy_widgets()


def _destroy_widgets():
    """
    Delete every top-level widget a test left behind.

    Closed windows otherwise live until the session ends, and each later
    QApplication.setStyleSheet re-polishes all of them: by the end of the
    suite a one-line theme change cost seconds.
    """
    from PyQt6.QtCore import QCoreApplication, QEvent, QThread
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        return
    for widget in app.topLevelWidgets():
        # Background workers parented to a window must finish before it goes.
        for thread in widget.findChildren(QThread):
            if thread.isRunning():
                cancel = getattr(thread, "cancel", None)
                if cancel:
                    cancel()
                thread.wait(5000)
        widget.close()
        widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
