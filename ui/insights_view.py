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
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPushButton, QSplitter, QStackedWidget, QTableView, QTextBrowser,
    QVBoxLayout, QWidget,
)

from ui.theme import palette, plain, readable, restyle
from core.insights import (
    FINDING_COLUMNS, RULES, SEVERITIES, SEVERITY_COLORS, Finding, analyse, counts,
    rule_for, rule_status,
)


def _plugin_label(plugin: str) -> str:
    return plugin.rsplit(".", 1)[-1]


def how_it_works_html(have: set[str], findings: list[Finding], dim: str,
                      ok: str, warn: str) -> str:
    """The "How Insights work" page: what the rules are, and which of them ran."""
    rows = []
    for rule, ran, produced, missing in rule_status(have, findings):
        if ran:
            state = (f"<span style='color:{warn}'><b>{produced} flagged</b></span>"
                     if produced else f"<span style='color:{ok}'>Ran, nothing flagged</span>")
        else:
            needs = ", ".join(_plugin_label(m) for m in missing)
            state = f"<span style='color:{dim}'>Waiting for {html.escape(needs)}</span>"
        attack = ", ".join(f"{i}" for i, _ in rule.attack)
        rows.append(
            f"<tr><td style='padding:6px 14px 6px 0;vertical-align:top'><b>"
            f"{html.escape(rule.name)}</b><br><span style='color:{dim}'>{attack}</span></td>"
            f"<td style='padding:6px 14px 6px 0;vertical-align:top'>{html.escape(rule.checks)}</td>"
            f"<td style='padding:6px 0;vertical-align:top;white-space:nowrap'>{state}</td></tr>")
    ran = sum(1 for _, r, _, _ in rule_status(have, findings) if r)
    return (
        "<h2>How Insights work</h2>"
        "<p>Insights is a set of fixed rules, not machine learning and not a "
        "malware verdict. Each rule reads the output of plugins you have already "
        "run on this image and compares it against how a normal Windows system "
        "looks: which parent starts which system process, where system programs "
        "live on disk, which memory should never be both writable and executable, "
        "and so on. Anything that does not match becomes a lead.</p>"
        "<p>A lead is a place to look, not a conclusion. Every finding says why the "
        "rule fired, how to confirm or dismiss it, and the innocent explanations "
        "examiners meet most often.</p>"
        "<p><b>Severity</b> is the rule's own weight: <i>High</i> means it rarely "
        "has an innocent cause (a hidden process, injected code); <i>Medium</i> "
        "deserves a look; <i>Low</i> and <i>Info</i> are context. Severities are "
        "fixed per rule, so the same evidence always gets the same weight.</p>"
        f"<p><b>{ran} of {len(RULES)} rules ran</b> on this image. A rule runs when "
        "the plugins it reads have output; <i>Collect Insight Data</i> runs the "
        "missing ones.</p>"
        "<table width='100%' cellspacing='0'>"
        f"<tr><th align='left' style='color:{dim}'>Rule</th>"
        f"<th align='left' style='color:{dim}'>What it checks</th>"
        f"<th align='left' style='color:{dim}'>On this image</th></tr>"
        + "".join(rows) + "</table>")


class FindingModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings: list[Finding] = []
        self.dark = True

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
            return QColor(readable(
                SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["info"]), self.dark))
        if role == Qt.ItemDataRole.ToolTipRole:
            return plain(finding.detail)
        return None


class _SeverityCard(QFrame):
    """A severity filter toggle: coloured dot, count, name. Click to filter."""
    clicked = pyqtSignal(str)

    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.setObjectName("insightCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"Show only {severity} findings")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 12, 4)
        layout.setSpacing(6)
        # The severity colour is data, so it is the one inline colour here.
        dot = QLabel("\u25cf")
        dot.setStyleSheet(f"color: {SEVERITY_COLORS[severity]}; background: transparent;")
        self.count_lbl = QLabel("0")
        self.count_lbl.setObjectName("insightCount")
        label = QLabel(severity.title())
        label.setObjectName("insightLabel")
        layout.addWidget(dot)
        layout.addWidget(self.count_lbl)
        layout.addWidget(label)

    def set_count(self, n: int):
        self.count_lbl.setText(f"{n:,}")

    def set_selected(self, selected: bool):
        self.setProperty("selected", selected)
        restyle(self)

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
        self.have: set[str] = set()
        self.dark = True
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
        header.addWidget(self.collect_btn, 0, Qt.AlignmentFlag.AlignTop)
        self.how_btn = QPushButton("How Insights Work")
        self.how_btn.setCheckable(True)
        self.how_btn.setToolTip("What the rules check, and which of them ran on this image")
        self.how_btn.toggled.connect(self._toggle_how)
        header.addWidget(self.how_btn, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        cards = QHBoxLayout()
        cards.setSpacing(6)
        self._severity = ""
        self.cards = {}
        for severity in SEVERITIES:
            card = _SeverityCard(severity)
            card.clicked.connect(self._filter_to)
            self.cards[severity] = card
            cards.addWidget(card)
        cards.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter findings")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(160)
        self.search.setMaximumWidth(280)
        self.search.textChanged.connect(lambda _: self._apply())
        cards.addWidget(self.search, 1)
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

        self.how = QTextBrowser()
        self.how.setOpenExternalLinks(False)
        self.stack.addWidget(self.how)

    # ── Data ──────────────────────────────────────────────────────────────────

    def set_dark(self, dark: bool):
        self.dark = dark
        self._dim = palette(dark)["text_dim"]
        self.model.dark = dark
        self.model.layoutChanged.emit()
        self._show_current()
        self._fill_how()

    def _fill_how(self):
        tokens = palette(self.dark)
        self.how.setHtml(how_it_works_html(
            self.have, self.findings, tokens["text_dim"],
            tokens["ok"], tokens["warn"]))

    def _toggle_how(self, on: bool):
        if on:
            self._fill_how()
            self.stack.setCurrentIndex(2)
        else:
            self.stack.setCurrentIndex(1 if self.findings else 0)

    def set_payloads(self, payloads: list[dict], missing: list[str] | None = None):
        self.set_findings(analyse(payloads), missing)

    def set_findings(self, findings: list[Finding], missing: list[str] | None = None,
                     have: set[str] | None = None):
        """`have` is the plugins with stored output, for the How Insights Work page."""
        self.findings = findings
        self.missing = list(missing or [])
        if have is not None:
            self.have = set(have)
        tally = counts(findings)
        for severity, card in self.cards.items():
            card.set_count(tally.get(severity, 0))
        # Nothing left to collect: the button goes rather than sitting there
        # disabled, reading like an action that cannot be taken.
        self.collect_btn.setEnabled(bool(self.missing))
        self.collect_btn.setVisible(bool(self.missing))
        self.collect_btn.setText(f"Collect Insight Data ({len(self.missing)})")
        if findings:
            noun = "lead" if len(findings) == 1 else "leads"
            self.summary_lbl.setText(
                f"{len(findings)} {noun} from the stored output, most severe first. "
                "Each is a starting point; confirm it against the evidence.")
        else:
            self.summary_lbl.setText(
                "Nothing flagged in the output run so far." if not self.missing else
                "Run the plugins the rules read to see findings.")
        if self.how_btn.isChecked():
            self._fill_how()
        else:
            self.stack.setCurrentIndex(1 if findings else 0)
        self._apply()

    def _filter_to(self, severity: str):
        self._severity = "" if self._severity == severity else severity
        for name, card in self.cards.items():
            card.set_selected(name == self._severity)
        self._apply()

    def visible_findings(self) -> list[Finding]:
        return list(self.model.findings)

    def _apply(self):
        wanted = getattr(self, "_severity", "")
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
        color = readable(SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["info"]),
                         self.model.dark)
        dim = self._dim
        evidence = "".join(
            f"<tr><td style='padding-right:12px;color:{dim}'>{html.escape(k)}</td>"
            f"<td><code>{html.escape(v)}</code></td></tr>" for k, v in finding.evidence)
        self.detail.setHtml(
            f"<p><b style='color:{color}'>{finding.severity.title()}</b>"
            f"<span style='color:{dim}'>&nbsp;&nbsp;{html.escape(finding.category)}</span></p>"
            f"<h3>{html.escape(finding.title)}</h3>"
            f"<p>{html.escape(finding.detail)}</p>"
            + (f"<p>{html.escape(finding.process)} <span style='color:{dim}'>(PID "
               f"{html.escape(finding.pid)})</span></p>"
               if finding.pid else "")
            + (f"<table>{evidence}</table>" if evidence else "")
            + self._rule_html(finding)
            + f"<p style='color:{dim}'>Source: {html.escape(finding.plugin)}</p>")

    def _rule_html(self, finding: Finding) -> str:
        """Why the rule behind a finding matters, and how to check it."""
        rule = rule_for(finding)
        if rule is None:
            return ""
        dim = self._dim

        def section(heading, text):
            return (f"<p style='margin-bottom:2px'><b>{html.escape(heading)}</b></p>"
                    f"<p style='margin-top:0'>{html.escape(text)}</p>")

        attack = ", ".join(f"{i} {n}" for i, n in rule.attack)
        return (f"<hr><p style='color:{dim}'>Rule: {html.escape(rule.name)}</p>"
                + section("What the rule checks", rule.checks)
                + section("Why it matters", rule.why)
                + section("How to check it", rule.verify)
                + section("Common innocent causes", rule.noise)
                + (section("MITRE ATT&CK", attack) if attack else ""))

    def _bookmark(self):
        finding = self.current()
        if finding is not None:
            self.bookmark_requested.emit(finding)

    def _activated(self, index):
        if 0 <= index.row() < len(self.model.findings):
            self.finding_activated.emit(self.model.findings[index.row()])
