"""Reaching any tab once there are too many to fit, and the sidebar toggle."""
from PyQt6.QtWidgets import QLabel

from ui.result_tabs import ResultTabs


def _tabs(n):
    tabs = ResultTabs()
    tabs.add_result_tab(QLabel("case"), "Case", closable=False, pinned=True)
    for i in range(n):
        tabs.add_result_tab(QLabel(str(i)), f"Plugin {i}")
    return tabs


def test_tab_list_lists_every_tab_and_switches(qapp):
    tabs = _tabs(12)
    assert tabs.list_btn.text() == "13"
    tabs._fill_tab_list()
    actions = [a for a in tabs.list_btn.menu().actions() if a.text().startswith("Plugin")]
    assert len(actions) == 12
    actions[7].trigger()
    assert tabs.tabText(tabs.currentIndex()) == "Plugin 7"
    tabs.removeTab(1)
    assert tabs.list_btn.text() == "12"


def test_cycling_wraps_both_ways(qapp):
    tabs = _tabs(3)
    tabs.setCurrentIndex(3)
    tabs.cycle(1)
    assert tabs.currentIndex() == 0
    tabs.cycle(-1)
    assert tabs.currentIndex() == 3


def test_sidebar_toggle_hides_shows_and_remembers(qapp, tmp_path):
    from core import settings
    from core.case import Case
    from ui.main_window import MainWindow
    window = MainWindow(Case.create(str(tmp_path), "Sidebar"))
    window.show()
    assert window.case_dock.isVisible() and window.sidebar_action.shortcut().toString() == "Ctrl+B"
    window.ribbon.sidebar_btn.click()
    assert not window.case_dock.isVisible()
    assert settings.load(refresh=True)["sidebar_visible"] is False
    window.close()
    reopened = MainWindow(Case.open(window.case.directory))
    reopened.show()
    assert not reopened.case_dock.isVisible()
    reopened.sidebar_action.trigger()
    assert reopened.case_dock.isVisible()
    reopened.close()
