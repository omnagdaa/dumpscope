"""
Construct every window and dialog under both palettes.

This exists because a refactor left `ui.wizard` importing a name that no longer
existed: nothing imported the module, so nothing failed until the New Case
button was pressed. A test that merely builds each widget catches that class of
mistake for the cost of a few hundred milliseconds.
"""

import importlib
import pkgutil

import pytest
from PyQt6.QtWidgets import QApplication

import ui
from ui.theme import build

UI_MODULES = sorted(
    module.name for module in pkgutil.iter_modules(ui.__path__)
)


@pytest.mark.parametrize("name", UI_MODULES)
def test_every_ui_module_imports(name):
    importlib.import_module(f"ui.{name}")


@pytest.mark.parametrize("dark", [True, False])
def test_case_manager_constructs(qapp, dark):
    from ui.case_manager import CaseManager

    manager = CaseManager(is_dark=dark)
    assert QApplication.instance().styleSheet(), "the launcher must theme itself"
    manager.deleteLater()


@pytest.mark.parametrize("dark", [True, False])
def test_wizard_constructs_and_steps(qapp, dark):
    from ui.wizard import CaseWizard

    wizard = CaseWizard()
    wizard.is_dark = dark
    wizard.apply_theme()
    for step in range(3):
        wizard.step_indicator.set_step(step)
    states = [circle.property("state") for circle in wizard.step_indicator.circles]
    assert states == ["done", "done", "active"]
    wizard.deleteLater()


def test_drop_zone_states(qapp):
    from ui.wizard import DropZone

    zone = DropZone()
    assert zone.property("state") == "idle"
    zone._update_style(hover=True)
    assert zone.property("state") == "hover"
    zone.file_path = "/tmp/image.raw"
    zone._update_style()
    assert zone.property("state") == "loaded"
    zone.deleteLater()


@pytest.mark.parametrize("dark", [True, False])
def test_result_panel_constructs_and_themes(qapp, dark):
    from ui.result_panel import ResultPanel

    qapp.setStyleSheet(build(dark=dark))
    panel = ResultPanel("Process List", "windows.pslist.PsList")
    panel.apply_theme(dark)
    panel.set_columns(["PID", "ImageFileName"])
    panel.append_rows([["4", "System"], ["372", "smss.exe"]])
    panel.set_finished(0)
    assert panel.status_dot.property("state") == "done"
    panel.deleteLater()


def test_case_tree_constructs(qapp):
    from ui.case_tree import CaseTree

    tree = CaseTree()
    tree.refresh([], [], [])
    tree.apply_theme(dark=False)
    tree.refresh(
        [{"id": 1, "path": "/nowhere/missing.raw", "display_name": "missing.raw"}],
        [], [],
    )
    tree.deleteLater()


def test_sorting_starts_disabled_and_enables_on_a_header_click(qapp):
    """
    Regression for a SIGSEGV.

    Sorting used to be enabled up front with the indicator hidden, and a slot
    on sortIndicatorChanged called setSortIndicatorShown straight back into the
    header. Qt emits that signal from inside QHeaderView::mouseReleaseEvent, so
    the slot re-entered the header's own mouse handling and the application
    crashed with no Python traceback. The switch is now driven by
    sectionClicked and deferred to the next event-loop pass.
    """
    from PyQt6.QtWidgets import QApplication
    from ui.result_panel import ResultPanel

    panel = ResultPanel("PsTree", "windows.pstree.PsTree")
    panel.set_columns(["PID", "ImageFileName"])
    panel.append_rows([["4", "System"], ["372", "smss.exe"], ["88", "Registry"]])

    header = panel.table.horizontalHeader()
    assert not panel.table.isSortingEnabled(), "source order must survive until asked"
    assert not header.isSortIndicatorShown()
    # vol3's emitted order carries meaning for pstree; it must be intact.
    assert [panel.model.row_values(r)[0] for r in range(3)] == ["4", "372", "88"]

    header.sectionClicked.emit(0)
    assert panel._sorting_enabled, "the click is recorded immediately…"
    assert not panel.table.isSortingEnabled(), "…but the header is not touched yet"

    QApplication.processEvents()          # let the deferred switch run
    assert panel.table.isSortingEnabled()
    assert header.isSortIndicatorShown()
    panel.deleteLater()


def test_a_second_header_click_does_not_re_enter(qapp):
    from PyQt6.QtWidgets import QApplication
    from ui.result_panel import ResultPanel

    panel = ResultPanel("PsList", "windows.pslist.PsList")
    panel.set_columns(["PID"])
    panel.append_rows([["4"], ["372"]])
    header = panel.table.horizontalHeader()
    header.sectionClicked.emit(0)
    QApplication.processEvents()
    # Once Qt owns the sorting, our slot must do nothing at all.
    enabled_before = panel.table.isSortingEnabled()
    header.sectionClicked.emit(0)
    header.sectionClicked.emit(0)
    QApplication.processEvents()
    assert panel.table.isSortingEnabled() == enabled_before
    panel.deleteLater()


# ── Window chrome ─────────────────────────────────────────────────────────────

def _window(tmp_path, name="Chrome Case"):
    from core.case import Case
    from ui.main_window import MainWindow

    return MainWindow(Case.create(str(tmp_path), name))


def test_the_case_identifies_itself_in_the_sidebar_not_a_title_bar(qapp, tmp_path):
    window = _window(tmp_path, "Operation Tidewater")
    assert window.case_tag.text() == "Operation Tidewater"
    # The header is inside the dock, so the case travels with the sidebar.
    assert window.case_dock.isAncestorOf(window.case_tag)
    assert window.case_dock.isAncestorOf(window.os_badge)
    assert not hasattr(window, "_build_topbar")
    window.close()


def test_the_os_badge_recovers_its_text_after_probing(qapp, tmp_path):
    """
    A QLabel shows a pixmap *or* text. Handing the badge a null pixmap while
    probing used to blank it permanently, because the OS it settled on was the
    one already set and the refresh was skipped.
    """
    window = _window(tmp_path)
    window._set_badge_probing()
    assert window.os_badge.text() == "Identifying…"
    window._update_os_badge()
    assert window.os_badge.text().startswith("Windows")
    window.close()


def test_the_ribbon_carries_the_theme_toggle_and_no_density_button(qapp, tmp_path):
    window = _window(tmp_path)
    ribbon = window.ribbon
    assert not hasattr(ribbon, "density_btn")
    assert ribbon.compact, "tiles are compact by default"

    dark_before = window.is_dark
    ribbon.theme_btn.click()
    assert window.is_dark is not dark_before
    assert ribbon.theme_btn.property("glyph") == ("moon" if window.is_dark else "sun")
    window.close()
