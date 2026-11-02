"""Typing, sorting, tree depth and filtering in the results model."""
import os
from PyQt6.QtCore import Qt

from ui.result_model import ResultFilterProxy, ResultTableModel

COLUMNS = ["TreeDepth", "PID", "Offset(V)", "ImageFileName", "CreateTime"]
ROWS = [
    ["0", "4",    "0x8e0f2a1c3000", "System",       "2024-01-15T09:00:00"],
    ["1", "100",  "0x8e0f2a1c9000", "smss.exe",     "2024-01-15T09:05:00"],
    ["2", "20",   "0x8e0f2a1c1000", "csrss.exe",    "2024-01-15T08:59:00"],
    ["1", "3",    "0xff0f2a1c1000", "winlogon.exe", "N/A"],
]


def _model():
    model = ResultTableModel()
    model.set_columns(COLUMNS)
    model.append_rows([list(row) for row in ROWS])
    return model


def _column(proxy, index):
    return [
        proxy.data(proxy.index(row, index), Qt.ItemDataRole.DisplayRole)
        for row in range(proxy.rowCount())
    ]


def test_tree_depth_is_consumed_not_displayed(qapp):
    model = _model()
    assert model.columns == ["PID", "Offset(V)", "ImageFileName", "CreateTime"]
    assert model.columnCount() == 4


def test_tree_depth_indents_the_first_column(qapp):
    model = _model()
    shown = [model.data(model.index(r, 0), Qt.ItemDataRole.DisplayRole) for r in range(4)]
    assert shown == ["4", "    100", "        20", "    3"]


def test_integers_sort_numerically(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    assert [v.strip() for v in _column(proxy, 0)] == ["3", "4", "20", "100"]


def test_hex_addresses_sort_numerically(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())
    proxy.sort(1, Qt.SortOrder.AscendingOrder)
    assert _column(proxy, 1) == [
        "0x8e0f2a1c1000", "0x8e0f2a1c3000", "0x8e0f2a1c9000", "0xff0f2a1c1000",
    ]


def test_timestamps_sort_chronologically_with_absent_values_last(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())
    proxy.sort(3, Qt.SortOrder.AscendingOrder)
    assert _column(proxy, 3) == [
        "2024-01-15T08:59:00", "2024-01-15T09:00:00", "2024-01-15T09:05:00", "N/A",
    ]


def test_substring_and_regex_filtering(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())

    proxy.set_filter("exe")
    assert proxy.rowCount() == 3

    proxy.set_filter(r"^(smss|csrss)\.exe$", use_regex=True)
    assert proxy.rowCount() == 2
    assert proxy.filter_is_valid_regex

    proxy.set_filter("")
    assert proxy.rowCount() == 4


def test_invalid_regex_is_reported_not_raised(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())
    proxy.set_filter("([unclosed", use_regex=True)
    assert not proxy.filter_is_valid_regex


def test_short_rows_are_padded_not_shifted(qapp):
    """
    The old whitespace-splitting parser dropped empty cells, so a row with a
    blank field shifted every later column one place left. Padding must happen
    on the right and leave earlier columns where they belong.
    """
    model = ResultTableModel()
    model.set_columns(["PID", "Name", "Path", "State"])
    model.append_rows([["820", "svchost.exe"]])
    assert model.row_values(0) == ["820", "svchost.exe", "", ""]


def test_a_theme_change_does_not_corrupt_the_proxys_index_mapping():
    """
    Toggling the theme with results on screen used to kill the process.

    apply_theme emitted a bare layoutChanged. Qt requires that signal to be
    preceded by layoutAboutToBeChanged; without it QSortFilterProxyModel
    rebuilds its mapping without saving the indexes the view still holds, and
    the next mouse move over the table dereferences one of them. It dies in
    QSortFilterProxyModel::parent with no Python traceback, because no Python
    frame is on the stack.
    """
    import subprocess
    import sys

    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_stress.py")
    proc = subprocess.run([sys.executable, script], capture_output=True,
                          text=True, timeout=180)
    assert proc.returncode == 0, (
        f"the result table crashed (exit {proc.returncode})\n{proc.stderr[-800:]}"
    )


# ── Sorting in the model ──────────────────────────────────────────────────────

def _pids(proxy):
    return [v.strip() for v in _column(proxy, 0)]


def test_descending_and_natural_order(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())
    proxy.sort(0, Qt.SortOrder.DescendingOrder)
    assert _pids(proxy) == ["100", "20", "4", "3"]
    proxy.sort(-1)
    assert _pids(proxy) == ["4", "100", "20", "3"], "-1 restores vol3's order"


def test_sorting_never_changes_what_is_stored(qapp):
    """result_payload feeds the database; a header click must not reorder it."""
    from ui.result_panel import ResultPanel
    panel = ResultPanel("PsTree", "windows.pstree.PsTree")
    panel.set_columns(COLUMNS)
    panel.append_rows([list(r) for r in ROWS])
    panel.proxy.sort(0, Qt.SortOrder.AscendingOrder)
    assert panel.model.row_values(0)[0] == "3", "the view follows the sort"
    assert [r[0] for r in panel.result_payload()["rows"]] == ["4", "100", "20", "3"]


def test_rows_streamed_while_sorted_are_folded_into_place(qapp):
    model = _model()
    proxy = ResultFilterProxy()
    proxy.setSourceModel(model)
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    model.append_rows([["0", "1", "0x1", "idle", "N/A"], ["0", "50", "0x2", "x", "N/A"]])
    assert _pids(proxy)[-2:] == ["1", "50"], "new rows wait at the bottom…"
    model._resort()                       # what the debounce timer fires
    assert _pids(proxy) == ["1", "3", "4", "20", "50", "100"]


def test_the_selection_follows_its_row_through_a_sort(qapp):
    from PyQt6.QtCore import QPersistentModelIndex
    model = _model()
    proxy = ResultFilterProxy()
    proxy.setSourceModel(model)
    held = QPersistentModelIndex(proxy.index(1, 2))          # smss.exe
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    assert held.isValid() and held.row() == 3
    assert proxy.data(proxy.index(held.row(), 2)) == "smss.exe"


def test_filter_and_sort_compose(qapp):
    proxy = ResultFilterProxy()
    proxy.setSourceModel(_model())
    proxy.set_filter("ss")                 # smss, csrss
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    assert [v.strip() for v in _column(proxy, 0)] == ["20", "100"]


def test_sorting_a_large_table_does_not_freeze_the_window(qapp):
    """Was ~5 s for 20k rows: Qt called a Python lessThan per comparison."""
    import random
    import time
    random.seed(7)
    model = ResultTableModel()
    model.set_columns(["PID", "Offset(V)", "CreateTime"])
    model.append_rows([[str(random.randint(1, 10**6)), hex(random.getrandbits(40)),
                        f"2024-01-{random.randint(10, 28)} 10:00:00"]
                       for _ in range(20_000)])
    proxy = ResultFilterProxy()
    proxy.setSourceModel(model)
    started = time.perf_counter()
    for column in range(3):
        proxy.sort(column, Qt.SortOrder.AscendingOrder)
    assert time.perf_counter() - started < 1.5
    times = [model.row_values(r)[2] for r in range(20_000)]
    assert times == sorted(times)
