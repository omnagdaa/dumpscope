"""
Table model for volatility3 results.

Replaces the old approach of stuffing strings into a QTableWidget. Two things
that bought:

* Typed sorting. vol3's CSV output is all text, so a QTableWidget sorts PIDs as
  "1, 10, 100, 2" and hex offsets lexically. This model infers a type per column
  from the values it sees and sorts on the parsed value, so numbers, hex
  addresses and timestamps order correctly.

* Scale. A widget-per-cell costs roughly a kilobyte each; plugins like filescan
  and handles emit six figures of rows. A model stores the strings and nothing
  else, and the view only materialises what is on screen.

The TreeDepth column that vol3's CSV renderer emits is consumed rather than
displayed: it drives indentation of the first visible column, which is what
makes pstree actually look like a tree.
"""

from __future__ import annotations

import re
from datetime import datetime

from PyQt6.QtCore import (
    QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt,
)
from PyQt6.QtGui import QColor, QFont

from ui.theme import mono_family, palette, plain

TREE_DEPTH_COLUMN = "TreeDepth"

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")

# Columns whose values are addresses even when they arrive as plain decimals.
_ADDRESS_HINTS = ("offset", "address", "base", "vaddr", "paddr", "start", "end")

TYPE_STRING, TYPE_INT, TYPE_HEX, TYPE_FLOAT, TYPE_DATETIME = range(5)



# How many values to look at before deciding a column's type. Sampling beyond
# the first screenful avoids a header-adjacent "N/A" fixing the type as string.
_TYPE_SAMPLE = 64


def _parse_datetime(text: str):
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _mono_font() -> QFont:
    """The fixed-width font for address columns, following the examiner's choice."""
    font = QFont()
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFamily(mono_family())
    return font


class ResultTableModel(QAbstractTableModel):
    """Streaming-friendly model: rows are appended in batches as vol3 emits them."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._faint = QColor(palette(dark=True)["text_faint"])
        self._mono = _mono_font()
        self._columns: list[str] = []
        self._rows: list[list[str]] = []
        self._depths: list[int] = []
        self._depth_index: int | None = None
        self._types: list[int] = []
        self._type_samples: list[int] = []
        self._type_locked: list[bool] = []

    # ── Population ────────────────────────────────────────────────────────────

    def set_columns(self, columns: list[str]) -> None:
        self.beginResetModel()
        self._depth_index = (
            columns.index(TREE_DEPTH_COLUMN) if TREE_DEPTH_COLUMN in columns else None
        )
        self._columns = [c for c in columns if c != TREE_DEPTH_COLUMN]
        self._rows = []
        self._depths = []
        self._types = [TYPE_STRING] * len(self._columns)
        self._type_samples = [0] * len(self._columns)
        self._type_locked = [False] * len(self._columns)
        self.endResetModel()

    def append_rows(self, rows: list[list[str]]) -> None:
        if not rows:
            return
        if not self._columns:
            # Results arrived before a header; synthesise one so nothing is lost.
            self.set_columns([f"Column {i + 1}" for i in range(len(rows[0]))])

        prepared: list[list[str]] = []
        depths: list[int] = []
        for row in rows:
            depth = 0
            if self._depth_index is not None and self._depth_index < len(row):
                row = list(row)
                raw_depth = row.pop(self._depth_index)
                try:
                    depth = int(raw_depth)
                except (TypeError, ValueError):
                    depth = 0
            if len(row) < len(self._columns):
                row = list(row) + [""] * (len(self._columns) - len(row))
            elif len(row) > len(self._columns):
                row = list(row[: len(self._columns)])
            prepared.append(row)
            depths.append(depth)
            self._observe_types(row)

        first = len(self._rows)
        self.beginInsertRows(QModelIndex(), first, first + len(prepared) - 1)
        self._rows.extend(prepared)
        self._depths.extend(depths)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows = []
        self._depths = []
        self._types = [TYPE_STRING] * len(self._columns)
        self._type_samples = [0] * len(self._columns)
        self._type_locked = [False] * len(self._columns)
        self.endResetModel()

    def _observe_types(self, row: list[str]) -> None:
        for col, value in enumerate(row):
            if col >= len(self._types) or self._type_locked[col]:
                continue
            value = value.strip()
            if not value or value in ("N/A", "-", "Disabled"):
                continue
            self._type_samples[col] += 1
            inferred = self._infer(value, self._columns[col])
            if self._type_samples[col] == 1:
                self._types[col] = inferred
            elif inferred != self._types[col]:
                # Mixed content: fall back to text so ordering stays stable.
                self._types[col] = TYPE_STRING
                self._type_locked[col] = True
            if self._type_samples[col] >= _TYPE_SAMPLE:
                self._type_locked[col] = True

    @staticmethod
    def _infer(value: str, column: str) -> int:
        if _HEX_RE.match(value):
            return TYPE_HEX
        if _INT_RE.match(value):
            lowered = column.lower()
            if any(h in lowered for h in _ADDRESS_HINTS):
                return TYPE_HEX
            return TYPE_INT
        if _FLOAT_RE.match(value):
            return TYPE_FLOAT
        if len(value) >= 10 and value[4:5] == "-" and _parse_datetime(value):
            return TYPE_DATETIME
        return TYPE_STRING

    # ── Qt interface ──────────────────────────────────────────────────────────

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self._columns[section] if section < len(self._columns) else None
        return section + 1

    # Text layout is linear in length and runs on every paint: one megabyte
    # command line freezes the table for seconds per repaint. Cells are capped
    # for display only; copy, export, bookmarks and filtering use the full value.
    DISPLAY_LIMIT = 1000

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if row >= len(self._rows) or col >= len(self._columns):
            return None
        value = self._rows[row][col]

        if role == Qt.ItemDataRole.DisplayRole:
            if len(value) > self.DISPLAY_LIMIT:
                value = value[:self.DISPLAY_LIMIT] + "…"
            if col == 0 and self._depths and self._depths[row]:
                return "    " * self._depths[row] + value
            return value

        if role == Qt.ItemDataRole.ToolTipRole:
            return plain(value) if len(value) > 40 else None

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if self._types[col] in (TYPE_INT, TYPE_HEX, TYPE_FLOAT):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.FontRole:
            # Built once. data() is called for every visible cell on every
            # repaint, and constructing a QFont each time showed up as a
            # measurable cost on wide tables.
            return self._mono if self._types[col] == TYPE_HEX else None

        if role == Qt.ItemDataRole.ForegroundRole:
            # Blank and N/A cells are dimmed so a sparse column reads as sparse
            # rather than as a wall of identical text. A brush cannot come from
            # the stylesheet, so the colour is taken from the palette instead.
            if not value or value == "N/A":
                return self._faint
            return None

        return None

    def apply_theme(self, dark: bool):
        """
        Follow the palette for the colours Qt paints with a brush.

        This announces a data change, not a layout change. A bare
        ``layoutChanged`` — without the ``layoutAboutToBeChanged`` that Qt
        requires to be paired with it — leaves QSortFilterProxyModel rebuilding
        its index mapping without having saved the old one, so every index the
        view is still holding points into freed memory. The next mouse move
        over the table dereferences one and the process dies in
        QSortFilterProxyModel::parent, with no Python traceback because no
        Python frame is involved.
        """
        self._faint = QColor(palette(dark=dark)["text_faint"])
        self._mono = _mono_font()
        if not self._rows or not self._columns:
            return
        self.dataChanged.emit(
            self.index(0, 0),
            self.index(len(self._rows) - 1, len(self._columns) - 1),
            [Qt.ItemDataRole.ForegroundRole],
        )

    # ── Sorting ───────────────────────────────────────────────────────────────

    def sort_key(self, row: int, col: int):
        """A comparable key for (row, col) honouring the column's inferred type."""
        value = self._rows[row][col].strip()
        kind = self._types[col]
        if not value or value == "N/A":
            # Absent values sort last in ascending order rather than first.
            return (1, 0) if kind != TYPE_STRING else (1, "")
        try:
            if kind == TYPE_HEX:
                return (0, int(value, 16) if value.lower().startswith("0x") else int(value))
            if kind == TYPE_INT:
                return (0, int(value))
            if kind == TYPE_FLOAT:
                return (0, float(value))
            if kind == TYPE_DATETIME:
                parsed = _parse_datetime(value)
                return (0, parsed.timestamp()) if parsed else (1, 0)
        except ValueError:
            return (1, 0)
        return (0, value.lower())

    # ── Accessors ─────────────────────────────────────────────────────────────

    @property
    def columns(self) -> list[str]:
        return list(self._columns)

    def row_values(self, row: int) -> list[str]:
        return list(self._rows[row]) if 0 <= row < len(self._rows) else []

    def row_dict(self, row: int) -> dict[str, str]:
        return dict(zip(self._columns, self.row_values(row)))

    def find_row(self, wanted: dict, keys: list[str] | None = None) -> int:
        """
        The index of the row matching `wanted`, or -1.

        Matching is by value across the named columns, because a tag recorded
        yesterday has to survive today's sort order and today's re-run. Columns
        the current output does not have are ignored rather than treated as a
        mismatch: plugins gain and lose columns between volatility3 releases,
        and a tag should not stop working because of it.
        """
        lookup = {name: index for index, name in enumerate(self._columns)}
        pairs = [
            (lookup[name], str(wanted[name]))
            for name in (keys or list(wanted))
            if name in lookup
        ]
        if not pairs:
            return -1
        for index, values in enumerate(self._rows):
            if all(column < len(values) and values[column] == value
                   for column, value in pairs):
                return index
        return -1


class ResultFilterProxy(QSortFilterProxyModel):
    """Case-insensitive substring filter across every column, with typed sorting."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._needle = ""
        self._regex: re.Pattern | None = None

    def set_filter(self, text: str, use_regex: bool = False) -> None:
        self._needle = text.strip().lower()
        self._regex = None
        if use_regex and text.strip():
            try:
                self._regex = re.compile(text, re.IGNORECASE)
            except re.error:
                self._regex = None
        self.invalidateFilter()

    @property
    def filter_is_valid_regex(self) -> bool:
        return self._regex is not None

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        """
        Compare on the model's typed key in Python.

        Qt's own comparison goes through QVariant, which cannot order the
        (present, value) tuples sort_key returns — they arrive as opaque
        objects and compare arbitrarily, silently degrading every sort to the
        display string.
        """
        model = self.sourceModel()
        if model is None:
            return super().lessThan(left, right)
        return model.sort_key(left.row(), left.column()) < model.sort_key(
            right.row(), right.column()
        )

    def filterAcceptsRow(self, source_row: int, parent: QModelIndex) -> bool:
        if not self._needle and self._regex is None:
            return True
        model = self.sourceModel()
        if model is None:
            return True
        values = model.row_values(source_row)
        if self._regex is not None:
            return any(self._regex.search(v) for v in values)
        return any(self._needle in v.lower() for v in values)
