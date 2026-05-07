import re
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QApplication, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit,
    QAbstractItemView, QStackedWidget, QPlainTextEdit,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor


# Columns that should display as hex addresses
HEX_COLUMNS = {"offset", "base", "start", "end", "address", "phys offset"}

# Known good column widths
COL_WIDTHS = {
    "PID":           65,  "PPID":        65,  "TID":          65,
    "Offset":       150,  "Base":        150,  "Start":       150,
    "End":          150,  "Address":     150,
    "ImageFileName":170,  "Name":        180,  "Process":     170,
    "Path":         280,  "File output": 260,
    "CreateTime":   195,  "ExitTime":    195,
    "LocalAddr":    210,  "ForeignAddr": 210,
    "State":        110,  "Proto":        70,  "Type":         90,
    "Owner":        140,  "Handles":      80,  "GrantedAccess":110,
    "Size":          90,  "Protection":  120,  "CommitCharge":  90,
    "Wow64":         65,  "Audit":        65,  "Enabled":       70,
    "BaseDllName":  200,  "FullDllPath":  300,
    "Symbol":       240,  "Module":       160,
    "Hive":         250,  "Key":          220,  "LastWriteTime":195,
    "Data":         300,  "Type ":         90,
    "Tag":           90,  "Info":         220,
    "Variable":     180,  "Value":        260,
}


class ResultPanel(QWidget):
    def __init__(self, plugin_name: str, parent=None):
        super().__init__(parent)
        self.plugin_name = plugin_name
        self._headers: list[str] = []
        self._separator_seen = False
        self._header_set = False
        self._raw_lines: list[str] = []
        self._pending_rows: list[list[str]] = []
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(120)
        self._flush_timer.timeout.connect(self._flush_rows)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setObjectName("resultToolbar")
        toolbar.setFixedHeight(46)
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(14, 0, 14, 0)
        tb.setSpacing(8)

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(
            "color: #f0883e; font-size: 10px; background: transparent;"
        )

        self.title_lbl = QLabel(f"  {self.plugin_name}")
        self.title_lbl.setStyleSheet(
            "font-size: 13px; font-weight: 700; background: transparent;"
        )

        self.row_count_lbl = QLabel("0 rows")
        self.row_count_lbl.setStyleSheet(
            "font-size: 11px; background: transparent;"
        )

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍  Filter…")
        self.search_box.setFixedWidth(200)
        self.search_box.setFixedHeight(28)
        self.search_box.textChanged.connect(self._filter_rows)
        self.search_box.setStyleSheet("")   # inherits from theme

        self.view_btn = QPushButton("📄 Raw")
        self.view_btn.setFixedWidth(72)
        self.view_btn.setFixedHeight(28)
        self.view_btn.setCheckable(True)
        self.view_btn.toggled.connect(self._toggle_view)

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(56)
        copy_btn.setFixedHeight(28)
        copy_btn.clicked.connect(self._copy_all)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(56)
        clear_btn.setFixedHeight(28)
        clear_btn.clicked.connect(self._clear)

        tb.addWidget(self.status_dot)
        tb.addWidget(self.title_lbl)
        tb.addStretch()
        tb.addWidget(self.row_count_lbl)
        tb.addSpacing(8)
        tb.addWidget(self.search_box)
        tb.addWidget(self.view_btn)
        tb.addWidget(copy_btn)
        tb.addWidget(clear_btn)

        # ── Stacked ───────────────────────────────────────────────────────────
        self.stack = QStackedWidget()

        # Table
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        # Raw log
        mono = QFont()
        mono.setFamily("JetBrains Mono")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(10)

        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_view.setFont(mono)
        self.raw_view.setObjectName("outputWindow")

        self.stack.addWidget(self.table)     # 0
        self.stack.addWidget(self.raw_view)  # 1

        layout.addWidget(toolbar)
        layout.addWidget(self.stack, 1)

    # ── Line ingestion ────────────────────────────────────────────────────────

    def append_line(self, line: str):
        self._raw_lines.append(line)
        self.raw_view.appendPlainText(line)

        stripped = line.strip()

        # Skip command/progress lines
        if not stripped:
            return
        if stripped.startswith(("$", "◌", "▶", "─")):
            return
        if stripped.startswith(("✓", "⚠", "[ERROR]")):
            return

        # Header detection
        if not self._header_set:
            # Separator line confirms the previous line was the header
            if set(stripped.replace(" ", "")) <= {"─", "-", "━"}:
                self._separator_seen = True
                return
            if not self._separator_seen:
                # This IS the header
                cols = self._split_cols(line)
                if len(cols) >= 2:
                    self._setup_table(cols)
                return
            # separator seen but header not set — shouldn't happen
            return

        # Data row
        cells = self._split_cols(line)
        if cells:
            self._pending_rows.append(cells)
            if not self._flush_timer.isActive():
                self._flush_timer.start()

    def _split_cols(self, line: str) -> list[str]:
        """Split vol3 output: columns separated by 2+ spaces."""
        parts = re.split(r"  +", line.strip())
        return [p.strip() for p in parts if p.strip()]

    def _setup_table(self, headers: list[str]):
        self.table.setSortingEnabled(False)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(0)
        self._headers = headers
        self._header_set = True

        for i, h in enumerate(headers):
            w = COL_WIDTHS.get(h, max(len(h) * 9, 80))
            w = min(w, 320)
            self.table.setColumnWidth(i, w)

        self.table.setSortingEnabled(True)

    def _flush_rows(self):
        if not self._pending_rows:
            self._flush_timer.stop()
            return

        self.table.setSortingEnabled(False)
        batch = self._pending_rows[:200]
        self._pending_rows = self._pending_rows[200:]
        n = len(self._headers)

        for cells in batch:
            # Pad/trim to column count
            while len(cells) < n:
                cells.append("")
            if len(cells) > n:
                cells = cells[:n - 1] + [" ".join(cells[n - 1:])]

            row = self.table.rowCount()
            self.table.insertRow(row)

            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                item.setFlags(
                    Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
                )
                self.table.setItem(row, col, item)

        self.table.setSortingEnabled(True)
        count = self.table.rowCount()
        self.row_count_lbl.setText(f"{count} rows")

        if not self._pending_rows:
            self._flush_timer.stop()

    # ── Filtering ─────────────────────────────────────────────────────────────

    def _filter_rows(self, text: str):
        text = text.lower()
        for row in range(self.table.rowCount()):
            if not text:
                self.table.setRowHidden(row, False)
                continue
            match = any(
                (item := self.table.item(row, col)) and text in item.text().lower()
                for col in range(self.table.columnCount())
            )
            self.table.setRowHidden(row, not match)

    # ── View toggle ───────────────────────────────────────────────────────────

    def _toggle_view(self, checked: bool):
        self.stack.setCurrentIndex(1 if checked else 0)
        self.view_btn.setText("📊 Table" if checked else "📄 Raw")

    # ── Status ────────────────────────────────────────────────────────────────

    def set_running(self, running: bool):
        if running:
            self.status_dot.setStyleSheet(
                "color: #f0883e; font-size: 10px; background: transparent;"
            )
            self.status_dot.setText("◉")
        else:
            self._flush_timer.stop()
            self._flush_rows()   # flush remainder
            self.status_dot.setStyleSheet(
                "color: #3daee9; font-size: 10px; background: transparent;"
            )
            self.status_dot.setText("●")

    def set_error(self, msg: str):
        self._flush_timer.stop()
        self.status_dot.setStyleSheet(
            "color: #e5534b; font-size: 10px; background: transparent;"
        )
        self.status_dot.setText("✕")
        self.raw_view.appendPlainText(f"\n[ERROR] {msg}")
        self.view_btn.setChecked(True)   # show raw on error

    # ── Copy / Clear ──────────────────────────────────────────────────────────

    def _copy_all(self):
        if self.stack.currentIndex() == 0:
            rows = []
            rows.append("\t".join(
                self.table.horizontalHeaderItem(c).text()
                for c in range(self.table.columnCount())
            ))
            for r in range(self.table.rowCount()):
                if not self.table.isRowHidden(r):
                    rows.append("\t".join(
                        (self.table.item(r, c).text()
                         if self.table.item(r, c) else "")
                        for c in range(self.table.columnCount())
                    ))
            QApplication.clipboard().setText("\n".join(rows))
        else:
            QApplication.clipboard().setText(self.raw_view.toPlainText())

    def _clear(self):
        self._flush_timer.stop()
        self.table.setRowCount(0)
        self.raw_view.clear()
        self._raw_lines.clear()
        self._headers.clear()
        self._pending_rows.clear()
        self._header_set = False
        self._separator_seen = False
        self.row_count_lbl.setText("0 rows")
