"""
Pinning, ordering, and the visible close button on result tabs.
"""

import pytest
from PyQt6.QtWidgets import QLabel

from ui.result_tabs import ResultTabs


@pytest.fixture
def tabs(qapp):
    widget = ResultTabs()
    widget.add_result_tab(QLabel("case"), "Case", closable=False, pinned=True)
    for name in ("PsList", "PsTree", "NetScan"):
        widget.add_result_tab(QLabel(name), name)
    return widget


def _titles(tabs):
    return [tabs.tabText(i) for i in range(tabs.count())]


def test_the_case_tab_is_pinned_and_not_closable(tabs):
    case = tabs.widget(0)
    assert tabs.is_pinned(case)
    assert case not in tabs.closable_widgets()


def test_pinning_moves_a_tab_ahead_of_the_unpinned_ones(tabs):
    netscan = tabs.widget(3)
    tabs.set_pinned(netscan, True)
    # Case and NetScan pinned, in the order they were pinned; the rest follow.
    assert _titles(tabs) == ["Case", "NetScan", "PsList", "PsTree"]


def test_unpinning_returns_a_tab_to_the_unpinned_group(tabs):
    netscan = tabs.widget(3)
    tabs.set_pinned(netscan, True)
    tabs.set_pinned(netscan, False)
    assert not tabs.is_pinned(netscan)
    # It sits after the pinned Case, among the unpinned tabs.
    assert _titles(tabs)[0] == "Case"
    assert set(_titles(tabs)[1:]) == {"PsList", "PsTree", "NetScan"}


def test_close_others_spares_pinned_tabs_and_the_kept_one(tabs):
    pslist = tabs.widget(1)
    closed = []
    tabs.tabCloseRequested.connect(closed.append)
    tabs._close_others(pslist)
    # Only PsTree and NetScan are asked to close; Case is pinned, PsList is kept.
    closed_titles = {tabs.tabText(i) for i in closed}
    assert closed_titles == {"PsTree", "NetScan"}


def test_close_all_leaves_the_pinned_tabs(tabs):
    closed = []
    tabs.tabCloseRequested.connect(closed.append)
    tabs._close_all()
    assert {tabs.tabText(i) for i in closed} == {"PsList", "PsTree", "NetScan"}


def test_every_tab_has_an_end_button(tabs):
    bar = tabs.tabBar()
    side = bar.ButtonPosition.RightSide
    for index in range(tabs.count()):
        assert bar.tabButton(index, side) is not None, "tabs need a visible affordance"


def test_a_pinned_tab_cannot_be_closed_through_the_window(qapp, tmp_path):
    from core.case import Case
    from ui.main_window import MainWindow

    window = MainWindow(Case.create(str(tmp_path), "Pin Case"))
    # The Case tab is at index 0, pinned. Asking to close it is a no-op.
    before = window.tabs.count()
    window._close_tab(0)
    assert window.tabs.count() == before
    window.close()
