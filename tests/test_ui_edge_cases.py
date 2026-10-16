"""
The windows under conditions an examiner can actually produce: no image,
an image that has since been deleted, a damaged case database, a damaged
settings file, and runs queued behind one another.

Modal dialogs are replaced with recorders: a real QMessageBox would block the
test forever, which is itself the hang these tests exist to rule out.
"""
import json
import os

import pytest
from PyQt6.QtWidgets import QMessageBox

from core import settings
from core.case import Case, remember_case
from core.plugins import PluginRegistry
from core.vol_runner import RUN_GATE


@pytest.fixture
def dialogs(monkeypatch):
    shown = []

    def record(kind):
        def _show(parent, title, text, *args, **kwargs):
            shown.append((kind, title, text))
            return QMessageBox.StandardButton.No
        return _show

    for kind in ("warning", "critical", "information", "question"):
        monkeypatch.setattr(QMessageBox, kind, staticmethod(record(kind)))
    return shown


@pytest.fixture
def registry():
    return PluginRegistry(None)       # the curated catalog, no vol3 import needed


def _window(case, registry):
    from ui.main_window import MainWindow
    window = MainWindow(case, registry=registry)
    return window


# ── Starting up ───────────────────────────────────────────────────────────────

def test_window_survives_a_damaged_settings_file(qapp, tmp_path, registry):
    """Regression: int("huge") on the stored font size crashed the constructor."""
    os.makedirs(os.path.dirname(settings.settings_file()), exist_ok=True)
    with open(settings.settings_file(), "w") as handle:
        json.dump({"font_size": "huge", "max_parallel_runs": "lots",
                   "desktop_notifications": "maybe"}, handle)
    settings._cache = None
    window = _window(Case.create(str(tmp_path), "Settings Case"), registry)
    assert RUN_GATE.limit == 1
    window.close()


def test_window_opens_with_a_corrupt_case_database(qapp, tmp_path, registry, dialogs):
    case = Case.create(str(tmp_path), "Broken DB")
    with open(case.db_path, "wb") as handle:
        handle.write(b"not a database" * 64)

    window = _window(case, registry)
    assert window.db is None, "analysis must still be possible without storage"
    assert any("database" in title.lower() for _, title, _ in dialogs)
    window.close()


def test_quick_analysis_window_has_no_database(qapp, tmp_path, registry):
    window = _window(Case.quick(str(tmp_path)), registry)
    assert window.db is None
    window.close()


# ── Running plugins without a usable image ────────────────────────────────────

def test_plugin_without_an_image_warns_and_does_not_launch(qapp, tmp_path, registry, dialogs):
    window = _window(Case.create(str(tmp_path), "No Image"), registry)
    window._on_plugin_clicked("windows.pslist.PsList")
    assert dialogs and dialogs[-1][1] == "No Image Loaded"
    assert window._runners == {}
    window.close()


def test_plugin_on_a_deleted_image_warns_and_does_not_launch(qapp, tmp_path, registry, dialogs):
    image = tmp_path / "gone.raw"
    image.write_bytes(b"\0" * 64)
    case = Case.create(str(tmp_path), "Gone Image", image_path=str(image))
    window = _window(case, registry)
    if window._os_probe is not None:
        window._os_probe.cancel()
        window._os_probe.wait(5000)
    image.unlink()

    window._on_plugin_clicked("windows.pslist.PsList")
    assert dialogs[-1][1] == "Image Missing"
    assert window._runners == {}
    window.close()


def test_unknown_plugin_id_is_refused(qapp, tmp_path, registry, dialogs):
    image = tmp_path / "img.raw"
    image.write_bytes(b"\0" * 64)
    window = _window(Case.create(str(tmp_path), "Unknown", image_path=str(image)), registry)
    if window._os_probe is not None:
        window._os_probe.cancel()
        window._os_probe.wait(5000)
    window._on_plugin_clicked("windows.not_a_plugin.Nope")
    assert dialogs[-1][1] == "Unknown Plugin"
    window.close()


# ── The parallel-runs setting ─────────────────────────────────────────────────

def test_parallel_runs_setting_applies_and_persists(qapp, tmp_path, registry):
    window = _window(Case.create(str(tmp_path), "Parallel"), registry)
    window._set_parallel_runs(3)
    assert RUN_GATE.limit == 3
    assert settings.load(refresh=True)["max_parallel_runs"] == 3

    checked = [a.data() for a in window.parallel_group.actions() if a.isChecked()]
    assert checked == [3], "the menu must show the limit that is in force"
    window.close()

    # A new window picks the stored value up.
    window = _window(Case.create(str(tmp_path), "Parallel 2"), registry)
    assert RUN_GATE.limit == 3
    assert [a.data() for a in window.parallel_group.actions() if a.isChecked()] == [3]
    window.close()


# ── Result panel states ───────────────────────────────────────────────────────

def test_queued_state_is_shown_then_replaced_by_progress(qapp):
    from ui.result_panel import ResultPanel
    panel = ResultPanel("PsList", "windows.pslist.PsList")
    panel.set_running(True)
    panel.set_queued(1)
    assert "Queued" in panel.stage_lbl.text()
    assert "1 other run " in panel.stage_lbl.text()
    panel.set_queued(2)
    assert "2 other runs" in panel.stage_lbl.text()
    panel.set_progress(40.0, "Scanning")
    assert panel.stage_lbl.text() == "Scanning"


def test_queued_signal_after_finish_is_ignored(qapp):
    from ui.result_panel import ResultPanel
    panel = ResultPanel("PsList", "windows.pslist.PsList")
    panel.set_running(True)
    panel.set_finished(0)
    panel.set_queued(1)                 # a late queued signal must not resurrect it
    assert "Queued" not in panel.stage_lbl.text()


@pytest.mark.parametrize("percent", [-50.0, 0.0, 100.0, 250.0, float("inf")])
def test_progress_is_clamped(qapp, percent):
    from ui.result_panel import ResultPanel
    panel = ResultPanel("PsList", "windows.pslist.PsList")
    panel.set_running(True)
    if percent == float("inf"):
        percent = 1e300
    panel.set_progress(percent, "x")
    assert 0 <= panel.progress.value() <= 100


def test_rows_wider_or_narrower_than_columns(qapp):
    from ui.result_panel import ResultPanel
    panel = ResultPanel("X", "x.X")
    panel.set_columns(["A", "B"])
    panel.append_rows([["1"], ["1", "2", "3"], []])
    assert panel.model.rowCount() == 3
    panel.model.data(panel.model.index(0, 1))
    panel.model.data(panel.model.index(2, 0))


def test_error_after_rows_keeps_the_rows(qapp):
    from ui.result_panel import ResultPanel
    panel = ResultPanel("X", "x.X")
    panel.set_running(True)
    panel.set_columns(["A"])
    panel.append_rows([["1"], ["2"]])
    panel.set_error("exit 1")
    assert panel.model.rowCount() == 2
    assert "ERROR: exit 1" in panel.log_view.toPlainText()


# ── Launcher ──────────────────────────────────────────────────────────────────

def test_launcher_empty_state_and_list_swap(qapp, tmp_path):
    from ui.case_manager import CaseManager
    manager = CaseManager()
    assert manager.recent_stack.currentIndex() == 1, "empty state should show"

    remember_case(Case.create(str(tmp_path), "Now There Is One"))
    manager._load_recent()
    assert manager.recent_stack.currentIndex() == 0
    assert manager.recent_list.count() == 1


def test_launcher_drops_cases_whose_folder_vanished(qapp, tmp_path):
    import shutil
    from ui.case_manager import CaseManager
    case = Case.create(str(tmp_path), "Ephemeral")
    remember_case(case)
    shutil.rmtree(case.directory)
    manager = CaseManager()
    assert manager.recent_list.count() == 0


@pytest.mark.parametrize("stamp", ["", "not a date", "2026-13-45T99:99:99",
                                   "2020-01-01T00:00:00+00:00", "2999-01-01T00:00:00"])
def test_friendly_time_never_raises(stamp):
    from ui.case_manager import _friendly_time
    assert isinstance(_friendly_time(stamp), str)
