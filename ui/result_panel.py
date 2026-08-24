"""
The per-plugin results pane: a live table, a raw log, and the controls around them.
"""

from __future__ import annotations

import csv
import json
import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction, QFont, QKeySequence
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QProgressBar,
    QPlainTextEdit, QPushButton, QSizePolicy, QStackedWidget, QTableView,
    QVBoxLayout, QWidget,
)

from ui.result_model import ResultFilterProxy, ResultTableModel
from ui.theme import restyle

# Sensible starting widths for columns vol3 emits constantly. Anything not
# listed is sized from its header text, bounded so one wide column cannot push
# every other column off screen.
COLUMN_WIDTHS = {
    "PID": 70, "PPID": 70, "TID": 70, "Threads": 75, "Handles": 75,
    "SessionId": 80, "Wow64": 65, "Offset": 155, "Offset(V)": 155,
    "Offset(P)": 155, "Base": 155, "Address": 155, "Start": 155, "End": 155,
    "ImageFileName": 170, "Name": 180, "Process": 170, "Path": 300,
    "File output": 240, "CreateTime": 190, "ExitTime": 190,
    "LocalAddr": 160, "ForeignAddr": 160, "LocalPort": 85, "ForeignPort": 85,
    "State": 120, "Proto": 70, "Owner": 150, "GrantedAccess": 120,
    "Size": 95, "Protection": 130, "BaseDllName": 200, "FullDllPath": 320,
    "Hive": 250, "Key": 240, "LastWriteTime": 190, "Data": 300,
    "Value": 260, "Variable": 180, "Type": 110, "Tag": 90,
}
_MIN_WIDTH, _MAX_WIDTH = 70, 340


class ResultPanel(QWidget):
    """
    Displays one plugin run. Rows stream in through `append_rows` while the
    plugin is still executing; the table stays sortable and filterable
    throughout.
    """

    cancel_requested = pyqtSignal()
    bookmark_requested = pyqtSignal(dict)   # the selected row as {column: value}

    def __init__(self, plugin_name: str, plugin_id: str = "", parent=None):
        super().__init__(parent)
        self.plugin_name = plugin_name
        self.plugin_id = plugin_id
        self._running = False
        self._log_lines: list[str] = []

        self.model = ResultTableModel(self)
        self.proxy = ResultFilterProxy(self)
        self.proxy.setSourceModel(self.model)

        self._build()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_toolbar())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_table())
        self.stack.addWidget(self._build_log())
        layout.addWidget(self.stack, 1)

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("resultToolbar")
        bar.setFixedHeight(46)
        row = QHBoxLayout(bar)
        row.setContentsMargins(14, 0, 14, 0)
        row.setSpacing(8)

        self.status_dot = QLabel("◉")
        self.status_dot.setObjectName("statusDot")
        self.status_dot.setProperty("state", "running")

        self.title_lbl = QLabel(self.plugin_name)
        self.title_lbl.setObjectName("panelTitle")

        self.progress = QProgressBar()
        self.progress.setFixedWidth(160)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setVisible(False)

        self.stage_lbl = QLabel("")
        self.stage_lbl.setObjectName("panelStage")
        self.stage_lbl.setMinimumWidth(0)
        self.stage_lbl.setSizePolicy(QSizePolicy.Policy.Ignored,
                                     QSizePolicy.Policy.Preferred)

        self.row_count_lbl = QLabel("0 rows")
        self.row_count_lbl.setObjectName("panelRowCount")

        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter rows…")
        self.filter_box.setClearButtonEnabled(True)
        self.filter_box.setFixedWidth(190)
        self.filter_box.setFixedHeight(28)
        self.filter_box.textChanged.connect(self._apply_filter)

        self.regex_chk = QCheckBox(".*")
        self.regex_chk.setToolTip("Treat the filter as a regular expression")
        self.regex_chk.toggled.connect(lambda _: self._apply_filter(self.filter_box.text()))

        self.cancel_btn = QPushButton("Stop")
        self.cancel_btn.setFixedSize(66, 28)
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.clicked.connect(self._on_cancel)

        self.view_btn = QPushButton("Log")
        self.view_btn.setFixedSize(62, 28)
        self.view_btn.setCheckable(True)
        self.view_btn.toggled.connect(self._toggle_view)

        export_btn = QPushButton("Export")
        export_btn.setFixedSize(78, 28)
        export_btn.clicked.connect(self.export_dialog)

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedSize(66, 28)
        copy_btn.clicked.connect(self.copy_visible)

        row.addWidget(self.status_dot)
        row.addWidget(self.title_lbl)
        row.addSpacing(10)
        row.addWidget(self.progress)
        row.addWidget(self.stage_lbl, 1)
        row.addWidget(self.row_count_lbl)
        row.addSpacing(6)
        row.addWidget(self.filter_box)
        row.addWidget(self.regex_chk)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.view_btn)
        row.addWidget(export_btn)
        row.addWidget(copy_btn)
        return bar

    def _build_table(self) -> QTableView:
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(23)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setHighlightSections(False)
        # Enabling sorting makes the view sort by section 0 straight away, which
        # scrambles output whose emitted order carries meaning — pstree's parent
        # and child rows are only adjacent in vol3's own ordering. Clearing the
        # indicator leaves rows in source order until a header is actually clicked.
        header.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        header.setSortIndicatorShown(False)
        header.sortIndicatorChanged.connect(
            lambda *_: header.setSortIndicatorShown(True)
        )

        copy_action = QAction(self.table)
        copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        copy_action.triggered.connect(self.copy_selection)
        self.table.addAction(copy_action)
        return self.table

    def _build_log(self) -> QPlainTextEdit:
        mono = QFont()
        mono.setFamily("JetBrains Mono")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(10)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(mono)
        self.log_view.setObjectName("outputWindow")
        self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.log_view.setMaximumBlockCount(5000)
        return self.log_view

    def apply_theme(self, dark: bool):
        """Pass the palette down to the model, which paints with brushes."""
        self.model.apply_theme(dark)

    # ── Streaming input ───────────────────────────────────────────────────────

    def set_columns(self, columns: list[str]):
        self.model.set_columns(columns)
        for index, name in enumerate(self.model.columns):
            width = COLUMN_WIDTHS.get(name, len(name) * 10 + 30)
            self.table.setColumnWidth(index, max(_MIN_WIDTH, min(width, _MAX_WIDTH)))

    def append_rows(self, rows: list[list[str]]):
        self.model.append_rows(rows)
        self._update_row_count()

    def append_log(self, line: str):
        self._log_lines.append(line)
        self.log_view.appendPlainText(line)

    def set_progress(self, percent: float, description: str):
        if not self._running:
            return
        self.progress.setVisible(True)
        self.progress.setValue(int(max(0.0, min(100.0, percent))))
        self.stage_lbl.setText(description)

    def _update_row_count(self):
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        self.row_count_lbl.setText(
            f"{shown:,} / {total:,} rows" if shown != total else f"{total:,} rows"
        )

    # ── State ─────────────────────────────────────────────────────────────────

    def set_running(self, running: bool):
        self._running = running
        self.cancel_btn.setVisible(running)
        self.progress.setVisible(running)
        self._set_state("running" if running else "done")
        if not running:
            self.stage_lbl.setText("")
            self.progress.setVisible(False)
            self._update_row_count()

    def set_finished(self, exit_code: int, cancelled: bool = False):
        self.set_running(False)
        if cancelled:
            self._set_state("cancelled")
            self.stage_lbl.setText("Cancelled")
        elif exit_code == 0:
            self._set_state("done")
            if self.model.rowCount() == 0:
                self.stage_lbl.setText("No results")
        else:
            self._set_state("error")

    def set_error(self, message: str):
        self.set_running(False)
        self._set_state("error")
        self.append_log("")
        self.append_log(f"ERROR: {message}")
        self.view_btn.setChecked(True)      # errors are only visible in the log

    def _set_state(self, state: str):
        glyphs = {"running": "◉", "done": "●", "error": "✕", "cancelled": "◌"}
        self.status_dot.setText(glyphs.get(state, "●"))
        self.status_dot.setProperty("state", state)
        restyle(self.status_dot)     # [state=…] rules need an explicit repolish

    def _on_cancel(self):
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("…")
        self.cancel_requested.emit()

    # ── Filter / view ─────────────────────────────────────────────────────────

    def _apply_filter(self, text: str):
        use_regex = self.regex_chk.isChecked()
        self.proxy.set_filter(text, use_regex=use_regex)
        invalid = use_regex and text.strip() and not self.proxy.filter_is_valid_regex
        self.filter_box.setProperty("invalid", "true" if invalid else "false")
        restyle(self.filter_box)
        self._update_row_count()

    def _toggle_view(self, checked: bool):
        self.stack.setCurrentIndex(1 if checked else 0)
        self.view_btn.setText("Table" if checked else "Log")

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_context_menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        menu = QMenu(self)
        menu.addAction("Copy Cell", lambda: self._copy_cell(index))
        menu.addAction("Copy Row", self.copy_selection)
        menu.addSeparator()
        menu.addAction("Add Bookmark", lambda: self._bookmark(index))
        menu.exec(self.table.viewport().mapToGlobal(point))

    def _copy_cell(self, index):
        QApplication.clipboard().setText(str(index.data() or ""))

    def _bookmark(self, index):
        source_row = self.proxy.mapToSource(index).row()
        payload = self.model.row_dict(source_row)
        payload["__plugin__"] = self.plugin_id or self.plugin_name
        self.bookmark_requested.emit(payload)

    # ── Copy / export ─────────────────────────────────────────────────────────

    def _visible_rows(self) -> list[list[str]]:
        return [
            self.model.row_values(self.proxy.mapToSource(self.proxy.index(r, 0)).row())
            for r in range(self.proxy.rowCount())
        ]

    def copy_visible(self):
        if self.stack.currentIndex() == 1:
            QApplication.clipboard().setText(self.log_view.toPlainText())
            return
        lines = ["\t".join(self.model.columns)]
        lines += ["\t".join(row) for row in self._visible_rows()]
        QApplication.clipboard().setText("\n".join(lines))

    def copy_selection(self):
        rows = sorted({i.row() for i in self.table.selectionModel().selectedIndexes()})
        if not rows:
            self.copy_visible()
            return
        lines = ["\t".join(self.model.columns)]
        for r in rows:
            source = self.proxy.mapToSource(self.proxy.index(r, 0)).row()
            lines.append("\t".join(self.model.row_values(source)))
        QApplication.clipboard().setText("\n".join(lines))

    def export_dialog(self, directory: str = ""):
        suggested = (self.plugin_id or self.plugin_name).replace(".", "_") + ".csv"
        path, selected = QFileDialog.getSaveFileName(
            self, "Export Results", os.path.join(directory or "", suggested),
            "CSV (*.csv);;JSON (*.json);;Tab-separated (*.tsv)",
        )
        if not path:
            return
        try:
            self.export_to(path, "json" if path.lower().endswith(".json")
                           else "tsv" if path.lower().endswith(".tsv") else "csv")
        except OSError as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
            return
        self.append_log(f"Exported {self.proxy.rowCount():,} rows to {path}")

    def export_to(self, path: str, fmt: str = "csv"):
        """Write the currently visible (filtered, sorted) rows to `path`."""
        columns = self.model.columns
        rows = self._visible_rows()
        if fmt == "json":
            payload = {
                "plugin": self.plugin_id or self.plugin_name,
                "columns": columns,
                "rows": [dict(zip(columns, row)) for row in rows],
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            return
        delimiter = "\t" if fmt == "tsv" else ","
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh, delimiter=delimiter)
            writer.writerow(columns)
            writer.writerows(rows)

    # ── Persistence helpers ───────────────────────────────────────────────────

    def result_payload(self) -> dict:
        """The full result set, for storing against the case."""
        return {
            "plugin": self.plugin_id or self.plugin_name,
            "columns": self.model.columns,
            "rows": [self.model.row_values(r) for r in range(self.model.rowCount())],
        }

    @property
    def log_text(self) -> str:
        return "\n".join(self._log_lines)
