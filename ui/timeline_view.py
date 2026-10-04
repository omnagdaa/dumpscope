"""
The Timeline tab: an Autopsy-style histogram of everything that happened on
the machine, above the list of events behind it.

The chart is painted by hand rather than pulled from a charting library so the
application keeps its three dependencies. Interaction follows Autopsy's
timeline: drag across the chart to zoom into a span, click a bar to list just
its events, double-click (or Reset) to see everything again, and toggle event
types from the legend.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta

from PyQt6.QtCore import (
    QAbstractTableModel, QModelIndex, QPointF, QRectF, Qt, pyqtSignal,
)
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QAbstractItemView, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPushButton, QSplitter, QStackedWidget, QTableView, QToolTip,
    QVBoxLayout, QWidget,
)

from core.timeline import (
    EVENT_COLUMNS, KIND_COLORS, KIND_LABELS, KINDS, Event, build_events,
    filter_events, format_time, histogram,
)
from ui.theme import palette


def _tick_label(moment: datetime, span: timedelta) -> str:
    if span <= timedelta(minutes=2):
        return moment.strftime("%H:%M:%S")
    if span <= timedelta(days=1):
        return moment.strftime("%H:%M")
    if span <= timedelta(days=60):
        return moment.strftime("%b %d %H:%M")
    return moment.strftime("%Y-%m-%d")


class TimelineChart(QWidget):
    """Stacked bars of events per time slice. Emits the span the user picks."""

    range_selected = pyqtSignal(object, object)     # start, end (datetimes)
    reset_requested = pyqtSignal()

    LEFT, RIGHT, TOP, BOTTOM = 46, 14, 12, 28

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(170)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.CrossCursor)
        self._events: list[Event] = []
        self._kinds: set[str] = {k for k, _, _ in KINDS}
        self._start: datetime | None = None
        self._end: datetime | None = None
        self._bins: list = []
        self._drag_from: float | None = None
        self._drag_to: float | None = None
        self._colors = palette(True)

    # ── Data ──────────────────────────────────────────────────────────────────

    def set_dark(self, dark: bool):
        self._colors = palette(dark)
        self.update()

    def set_events(self, events: list[Event], start=None, end=None):
        self._events = events
        if events:
            self._start = start or events[0].time
            self._end = end or events[-1].time
        else:
            self._start = self._end = None
        self._rebin()

    def set_kinds(self, kinds: set[str]):
        self._kinds = set(kinds)
        self._rebin()

    def view_range(self):
        return self._start, self._end

    def bucket_count(self) -> int:
        return max(10, min(160, int(self._plot_rect().width() // 9)))

    def _rebin(self):
        if self._start is None:
            self._bins = []
        else:
            visible = [e for e in self._events if e.kind in self._kinds]
            self._bins = histogram(visible, self._start, self._end, self.bucket_count())
        self.update()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._rebin()

    # ── Geometry ──────────────────────────────────────────────────────────────

    def _plot_rect(self) -> QRectF:
        return QRectF(self.LEFT, self.TOP,
                      max(1, self.width() - self.LEFT - self.RIGHT),
                      max(1, self.height() - self.TOP - self.BOTTOM))

    def _span(self) -> timedelta:
        if self._start is None:
            return timedelta(0)
        return max(self._end - self._start, timedelta(seconds=1))

    def time_at(self, x: float) -> datetime | None:
        if self._start is None:
            return None
        rect = self._plot_rect()
        fraction = min(max((x - rect.left()) / rect.width(), 0.0), 1.0)
        return self._start + self._span() * fraction

    def _bucket_at(self, x: float) -> int:
        rect = self._plot_rect()
        if not self._bins or not rect.left() <= x <= rect.right():
            return -1
        return min(int((x - rect.left()) / rect.width() * len(self._bins)),
                   len(self._bins) - 1)

    def _bucket_range(self, index: int):
        width = self._span() / len(self._bins)
        start = self._start + width * index
        return start, start + width

    # ── Painting ──────────────────────────────────────────────────────────────

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        colors = self._colors
        p.fillRect(self.rect(), QColor(colors["surface"]))
        rect = self._plot_rect()
        small = QFont(self.font())
        small.setPointSizeF(max(7.0, self.font().pointSizeF() * 0.8))
        p.setFont(small)

        if not self._bins:
            p.setPen(QColor(colors["text_faint"]))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No events to chart")
            return

        peak = max((sum(c[k] for k in self._kinds if k in c) for c in self._bins),
                   default=0) or 1
        grid = QPen(QColor(colors["border"]))
        for i in range(5):
            y = rect.bottom() - rect.height() * i / 4
            p.setPen(grid)
            p.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            p.setPen(QColor(colors["text_faint"]))
            p.drawText(QRectF(0, y - 8, self.LEFT - 6, 16),
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       f"{round(peak * i / 4):,}")

        bar_w = rect.width() / len(self._bins)
        order = [k for k, _, _ in KINDS if k in self._kinds]
        for i, counter in enumerate(self._bins):
            y = rect.bottom()
            x = rect.left() + i * bar_w
            for kind in order:
                n = counter.get(kind, 0)
                if not n:
                    continue
                h = max(n / peak * rect.height(), 1.0)
                y -= h
                p.fillRect(QRectF(x + 0.5, y, max(bar_w - 1.5, 1.0), h),
                           QColor(KIND_COLORS[kind]))

        p.setPen(QColor(colors["text_dim"]))
        span = self._span()
        for i in range(5):
            moment = self._start + span * (i / 4)
            x = rect.left() + rect.width() * i / 4
            if i == 0:
                box, align = QRectF(x, rect.bottom() + 4, 140, 18), Qt.AlignmentFlag.AlignLeft
            elif i == 4:
                box, align = QRectF(x - 140, rect.bottom() + 4, 140, 18), Qt.AlignmentFlag.AlignRight
            else:
                box, align = (QRectF(x - 70, rect.bottom() + 4, 140, 18),
                              Qt.AlignmentFlag.AlignHCenter)
            p.drawText(box, align | Qt.AlignmentFlag.AlignTop, _tick_label(moment, span))

        if self._drag_from is not None and self._drag_to is not None:
            left, right = sorted((self._drag_from, self._drag_to))
            band = QColor(colors["accent"])
            band.setAlpha(60)
            p.fillRect(QRectF(left, rect.top(), right - left, rect.height()), band)
            p.setPen(QPen(QColor(colors["accent"])))
            p.drawRect(QRectF(left, rect.top(), right - left, rect.height()))

    # ── Interaction ───────────────────────────────────────────────────────────

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self._bins:
            self._drag_from = self._drag_to = event.position().x()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        x = event.position().x()
        if self._drag_from is not None:
            self._drag_to = x
            self.update()
            return
        index = self._bucket_at(x)
        if index >= 0:
            start, end = self._bucket_range(index)
            counter = self._bins[index]
            lines = [f"{format_time(start)} – {_tick_label(end, self._span())}"]
            lines += [f"{KIND_LABELS[k]}: {counter[k]:,}"
                      for k, _, _ in KINDS if counter.get(k) and k in self._kinds]
            QToolTip.showText(event.globalPosition().toPoint(), "\n".join(lines), self)
        else:
            QToolTip.hideText()

    def mouseReleaseEvent(self, event):
        if self._drag_from is None:
            return
        left, right = sorted((self._drag_from, self._drag_to or self._drag_from))
        self._drag_from = self._drag_to = None
        self.update()
        if right - left >= 6:
            self.range_selected.emit(self.time_at(left), self.time_at(right))
        else:
            index = self._bucket_at(left)
            if index >= 0:
                self.range_selected.emit(*self._bucket_range(index))

    def mouseDoubleClickEvent(self, _event):
        self.reset_requested.emit()

    def wheelEvent(self, event):
        if self._start is None:
            return
        anchor = self.time_at(event.position().x())
        factor = 0.8 if event.angleDelta().y() > 0 else 1.25
        span = self._span() * factor
        if span < timedelta(seconds=2):
            return
        fraction = (anchor - self._start) / self._span()
        start = anchor - span * fraction
        self.range_selected.emit(start, start + span)


class EventModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.events: list[Event] = []

    def set_events(self, events: list[Event]):
        self.beginResetModel()
        self.events = events
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.events)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(EVENT_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return EVENT_COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.events):
            return None
        event = self.events[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return event.as_row()[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 1:
            return QColor(KIND_COLORS.get(event.kind, KIND_COLORS["other"]))
        if role == Qt.ItemDataRole.ToolTipRole:
            return event.detail or event.summary
        return None


class TimelineView(QWidget):
    """
    The whole tab. `collect_requested(list)` asks the window to run the
    plugins the timeline still lacks; `event_activated(Event)` reports a
    double-clicked row.
    """

    collect_requested = pyqtSignal(list)
    event_activated = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.events: list[Event] = []
        self.missing: list[str] = []
        self._kinds = {k for k, _, _ in KINDS}
        self._range = (None, None)
        self._chips: dict[str, QPushButton] = {}
        self._build()
        self._apply()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("Incident Timeline")
        title.setObjectName("overviewTitle")
        self.summary_lbl = QLabel("")
        self.summary_lbl.setObjectName("overviewBlurb")
        titles.addWidget(title)
        titles.addWidget(self.summary_lbl)
        header.addLayout(titles, 1)

        self.collect_btn = QPushButton("Collect Timeline Data")
        self.collect_btn.setObjectName("primaryButton")
        self.collect_btn.setToolTip("Run the plugins the timeline draws on that have "
                                    "not been run on this image yet.")
        self.collect_btn.clicked.connect(lambda: self.collect_requested.emit(list(self.missing)))
        self.reset_btn = QPushButton("Reset Zoom")
        self.reset_btn.clicked.connect(self.reset_zoom)
        self.export_btn = QPushButton("Export CSV…")
        self.export_btn.clicked.connect(self._export)
        for button in (self.reset_btn, self.export_btn, self.collect_btn):
            header.addWidget(button)
        layout.addLayout(header)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        # Empty state.
        empty = QFrame()
        empty.setObjectName("launcherEmpty")
        empty_layout = QVBoxLayout(empty)
        empty_layout.addStretch()
        heading = QLabel("No timeline yet")
        heading.setObjectName("launcherEmptyTitle")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_lbl = QLabel(
            "The timeline is built from plugin output already in the case: "
            "process creation and exit, DLL loads, network connections, logon "
            "sessions and program execution. Run Process List, DLL List and "
            "Net Scan, or collect everything it uses in one go.")
        self.empty_lbl.setObjectName("launcherEmptyText")
        self.empty_lbl.setWordWrap(True)
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_btn = QPushButton("Collect Timeline Data")
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

        # Populated state.
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(8)

        legend = QHBoxLayout()
        legend.setSpacing(6)
        for key, label, color in KINDS:
            chip = QPushButton(label)
            chip.setCheckable(True)
            chip.setChecked(True)
            chip.setObjectName("timelineChip")
            chip.setProperty("kind", key)
            chip.setStyleSheet(
                f"QPushButton#timelineChip:checked {{ border-left: 4px solid {color}; }}"
                f"QPushButton#timelineChip {{ border-left: 4px solid transparent; }}")
            chip.toggled.connect(lambda on, k=key: self._toggle_kind(k, on))
            self._chips[key] = chip
            legend.addWidget(chip)
        legend.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter events…  (process, PID, path, address)")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(300)
        self.search.textChanged.connect(lambda _: self._apply())
        legend.addWidget(self.search)
        body_layout.addLayout(legend)

        split = QSplitter(Qt.Orientation.Vertical)
        self.chart = TimelineChart()
        self.chart.range_selected.connect(self.zoom_to)
        self.chart.reset_requested.connect(self.reset_zoom)
        split.addWidget(self.chart)

        table_box = QWidget()
        table_layout = QVBoxLayout(table_box)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(4)
        self.range_lbl = QLabel("")
        self.range_lbl.setObjectName("panelStage")
        table_layout.addWidget(self.range_lbl)
        self.model = EventModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header_view.setStretchLastSection(False)
        for column, width in enumerate((200, 130, 64, 150, 520, 90)):
            self.table.setColumnWidth(column, width)
        self.table.doubleClicked.connect(self._activated)
        table_layout.addWidget(self.table)
        split.addWidget(table_box)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        body_layout.addWidget(split, 1)
        self.stack.addWidget(body)

    # ── Data ──────────────────────────────────────────────────────────────────

    def set_dark(self, dark: bool):
        self.chart.set_dark(dark)

    def set_payloads(self, payloads: list[dict], missing: list[str] | None = None):
        """Rebuild from stored output; keeps the zoom if it still makes sense."""
        self.set_events(build_events(payloads), missing)

    def set_events(self, events: list[Event], missing: list[str] | None = None):
        self.events = events
        self.missing = list(missing or [])
        start, end = self._range
        if events and start is not None and (end < events[0].time or start > events[-1].time):
            self._range = (None, None)
        for key, chip in self._chips.items():
            n = sum(1 for e in events if e.kind == key)
            chip.setText(f"{KIND_LABELS[key]}  {n:,}")
            chip.setVisible(n > 0)
        self.collect_btn.setEnabled(bool(self.missing))
        self.collect_btn.setText(
            f"Collect Timeline Data ({len(self.missing)})" if self.missing
            else "Timeline Data Collected")
        self.stack.setCurrentIndex(1 if events else 0)
        self._apply()

    def zoom_to(self, start, end):
        if start is None or end is None or not self.events:
            return
        if end <= start:
            end = start + timedelta(seconds=1)
        self._range = (start, end)
        self._apply()

    def reset_zoom(self):
        self._range = (None, None)
        self._apply()

    def _toggle_kind(self, kind: str, on: bool):
        if on:
            self._kinds.add(kind)
        else:
            self._kinds.discard(kind)
        self._apply()

    def visible_events(self) -> list[Event]:
        return list(self.model.events)

    def _apply(self):
        start, end = self._range
        self.chart.set_kinds(self._kinds)
        self.chart.set_events(self.events, start, end)
        shown = filter_events(self.events, self._kinds, start, end, self.search.text())
        self.model.set_events(shown)
        if self.events:
            first, last = self.events[0].time, self.events[-1].time
            self.summary_lbl.setText(
                f"{len(self.events):,} events from {format_time(first)} to "
                f"{format_time(last)} · drag across the chart to zoom, "
                "click a bar to list its events, double-click to reset")
        else:
            self.summary_lbl.setText("Nothing on the timeline yet.")
        if start is not None:
            self.range_lbl.setText(
                f"{len(shown):,} events between {format_time(start)} and {format_time(end)}")
        else:
            self.range_lbl.setText(f"{len(shown):,} events")
        self.reset_btn.setEnabled(start is not None)
        self.export_btn.setEnabled(bool(shown))

    def _activated(self, index):
        if 0 <= index.row() < len(self.model.events):
            self.event_activated.emit(self.model.events[index.row()])

    def export_csv(self, path: str) -> int:
        events = self.model.events
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(EVENT_COLUMNS + ["Detail"])
            for event in events:
                writer.writerow(event.as_row() + [event.detail])
        return len(events)

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Timeline", "timeline.csv",
                                              "CSV (*.csv)")
        if path:
            self.export_csv(path)
