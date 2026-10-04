"""
The Insights tab: automatic triage of everything run so far.

Findings come from core.insights. The tab shows how many there are at each
severity, lists them most severe first, and explains the selected one with the
evidence behind it. A finding can be bookmarked straight into the case so it
lands in the report with the examiner's other findings.
"""

from __future__ import annotations

import html

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPushButton, QSplitter, QStackedWidget, QTableView, QTextBrowser,
    QVBoxLayout, QWidget,
)

from ui.theme import palette
from core.insights import (
    FINDING_COLUMNS, SEVERITIES, SEVERITY_COLORS, Finding, analyse, counts,
)


class FindingModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings: list[Finding] = []

    def set_findings(self, findings: list[Finding]):
        self.beginResetModel()
        self.findings = findings
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.findings)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(FINDING_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return FINDING_COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.findings):
            return None
        finding = self.findings[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return finding.as_row()[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 0:
            return QColor(SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["info"]))
        if role == Qt.ItemDataRole.ToolTipRole:
            return finding.detail
        return None


class _SeverityCard(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.setObjectName("insightCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        color = SEVERITY_COLORS[severity]
        self.setStyleSheet(f"QFrame#insightCard {{ border-left: 4px solid {color}; }}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(0)
        self.count_lbl = QLabel("0")
        self.count_lbl.setObjectName("insightCount")
        label = QLabel(severity.title())
        label.setObjectName("insightLabel")
        layout.addWidget(self.count_lbl)
        layout.addWidget(label)

    def set_count(self, n: int):
        self.count_lbl.setText(f"{n:,}")

    def mousePressEvent(self, event):
        self.clicked.emit(self.severity)
        super().mousePressEvent(event)


class InsightsView(QWidget):
    collect_requested = pyqtSignal(list)
    bookmark_requested = pyqtSignal(object)          # Finding
    finding_activated = pyqtSignal(object)           # Finding

    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings: list[Finding] = []
        self.missing: list[str] = []
        self._dim = palette(True)["text_dim"]
        self._build()
        self._apply()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("Insights")
        title.setObjectName("overviewTitle")
        self.summary_lbl = QLabel("")
        self.summary_lbl.setObjectName("overviewBlurb")
        self.summary_lbl.setWordWrap(True)
        titles.addWidget(title)
        titles.addWidget(self.summary_lbl)
        header.addLayout(titles, 1)
        self.collect_btn = QPushButton("Collect Insight Data")
        self.collect_btn.setObjectName("primaryButton")
        self.collect_btn.setToolTip("Run the plugins the triage rules read that have "
                                    "not been run on this image yet.")
        self.collect_btn.clicked.connect(lambda: self.collect_requested.emit(list(self.missing)))
        header.addWidget(self.collect_btn)
        layout.addLayout(header)

        cards = QHBoxLayout()
        cards.setSpacing(10)
        self.cards = {}
        for severity in SEVERITIES:
            card = _SeverityCard(severity)
            card.clicked.connect(self._filter_to)
            self.cards[severity] = card
            cards.addWidget(card)
        cards.addStretch()
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All severities", "")
        for severity in SEVERITIES:
            self.severity_filter.addItem(severity.title(), severity)
        self.severity_filter.currentIndexChanged.connect(lambda _: self._apply())
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter findings…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(240)
        self.search.textChanged.connect(lambda _: self._apply())
        cards.addWidget(self.severity_filter)
        cards.addWidget(self.search)
        layout.addLayout(cards)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        empty = QFrame()
        empty.setObjectName("launcherEmpty")
        empty_layout = QVBoxLayout(empty)
        empty_layout.addStretch()
        heading = QLabel("No insights yet")
        heading.setObjectName("launcherEmptyTitle")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_lbl = QLabel(
            "Insights look across the stored output for hidden processes, wrong "
            "parents, lookalike names, suspicious paths and command lines, "
            "injected code, odd network use and suspicious services.")
        self.empty_lbl.setObjectName("launcherEmptyText")
        self.empty_lbl.setWordWrap(True)
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_btn = QPushButton("Collect Insight Data")
        empty_btn.setObjectName("primaryButton")
        empty_btn.clicked.connect(lambda: self.collect_requested.emit(list(self.missing)))
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(empty_btn)
        row.addStretch()
        empty_layout.addWidget(heading)
        empty_layout.addWidget(self.empty_lbl)
        empty_layout.addSpacing(8)
        empty_layout.addLayout(row)
        empty_layout.addStretch()
        self.stack.addWidget(empty)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.model = FindingModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((80, 170, 330, 60, 130, 320, 90)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(self._show_current)
        self.table.doubleClicked.connect(self._activated)
        split.addWidget(self.table)

        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(0, 0, 0, 0)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        side_layout.addWidget(self.detail, 1)
        self.bookmark_btn = QPushButton("Bookmark as Finding")
        self.bookmark_btn.setEnabled(False)
        self.bookmark_btn.clicked.connect(self._bookmark)
        side_layout.addWidget(self.bookmark_btn)
        split.addWidget(side)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        self.stack.addWidget(split)

    # ── Data ──────────────────────────────────────────────────────────────────

    def set_dark(self, dark: bool):
        self._dim = palette(dark)["text_dim"]
        self._show_current()

    def set_payloads(self, payloads: list[dict], missing: list[str] | None = None):
        self.set_findings(analyse(payloads), missing)

    def set_findings(self, findings: list[Finding], missing: list[str] | None = None):
        self.findings = findings
        self.missing = list(missing or [])
        tally = counts(findings)
        for severity, card in self.cards.items():
            card.set_count(tally.get(severity, 0))
        self.collect_btn.setEnabled(bool(self.missing))
        self.collect_btn.setText(
            f"Collect Insight Data ({len(self.missing)})" if self.missing
            else "Insight Data Collected")
        if findings:
            self.summary_lbl.setText(
                f"{len(findings)} lead(s) from the stored output, most severe first. "
                "These are starting points — check the evidence before relying on one.")
        else:
            self.summary_lbl.setText(
                "Nothing flagged in the output run so far." if not self.missing else
                "Run the plugins the rules read to see findings.")
        self.stack.setCurrentIndex(1 if findings else 0)
        self._apply()

    def _filter_to(self, severity: str):
        index = self.severity_filter.findData(severity)
        self.severity_filter.setCurrentIndex(
            0 if self.severity_filter.currentIndex() == index else index)

    def visible_findings(self) -> list[Finding]:
        return list(self.model.findings)

    def _apply(self):
        wanted = self.severity_filter.currentData() if hasattr(self, "severity_filter") else ""
        needle = self.search.text().strip().lower() if hasattr(self, "search") else ""
        shown = [
            f for f in self.findings
            if (not wanted or f.severity == wanted)
            and (not needle or needle in " ".join(f.as_row()).lower())
        ]
        self.model.set_findings(shown)
        if shown:
            self.table.selectRow(0)
        else:
            self.detail.setHtml("")
            self.bookmark_btn.setEnabled(False)

    def current(self) -> Finding | None:
        row = self.table.currentIndex().row()
        return self.model.findings[row] if 0 <= row < len(self.model.findings) else None

    def _show_current(self, *_):
        finding = self.current()
        self.bookmark_btn.setEnabled(finding is not None)
        if finding is None:
            self.detail.setHtml("")
            return
        color = SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["info"])
        dim = self._dim
        evidence = "".join(
            f"<tr><td style='padding-right:12px;color:{dim}'>{html.escape(k)}</td>"
            f"<td><code>{html.escape(v)}</code></td></tr>" for k, v in finding.evidence)
        self.detail.setHtml(
            f"<p><b style='color:{color}'>{finding.severity.upper()}</b> · "
            f"{html.escape(finding.category)}</p>"
            f"<h3>{html.escape(finding.title)}</h3>"
            f"<p>{html.escape(finding.detail)}</p>"
            + (f"<p>PID <b>{html.escape(finding.pid)}</b> · {html.escape(finding.process)}</p>"
               if finding.pid else "")
            + (f"<table>{evidence}</table>" if evidence else "")
            + f"<p style='color:{dim}'>From {html.escape(finding.plugin)}</p>")

    def _bookmark(self):
        finding = self.current()
        if finding is not None:
            self.bookmark_requested.emit(finding)

    def _activated(self, index):
        if 0 <= index.row() < len(self.model.findings):
            self.finding_activated.emit(self.model.findings[index.row()])
