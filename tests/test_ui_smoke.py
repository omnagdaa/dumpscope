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
