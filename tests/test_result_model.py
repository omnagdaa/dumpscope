"""Typing, sorting, tree depth and filtering in the results model."""
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
