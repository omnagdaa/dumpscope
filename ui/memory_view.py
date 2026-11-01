"""
The Memory Usage tab: which programs held the machine's memory when the image
was taken, drawn as a treemap the way WinDirStat and WizTree draw a disk.

Every box is one process, its area proportional to the chosen memory figure.
Processes are grouped by program (by executable path), and each program's
icon, taken from the image itself, sits in the middle of its group. Hovering
shows the process's details; double-clicking a program zooms into it.

The data comes from DumpScope's bundled plugin (dumpscope.procmem.ProcMem);
see core.memory_map.
"""

from __future__ import annotations

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush, QColor, QFont, QFontMetrics, QIcon, QImage, QLinearGradient, QPainter,
    QPainterPath, QPen, QPixmap,
)
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMenu, QPushButton, QSplitter, QStackedWidget, QToolTip,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.memory_map import (
    DEFAULT_METRIC, MEMORY_PLUGIN, METRICS, METRIC_LABELS, Program, colour_for,
    format_bytes, ranked,
)
from core.treemap import Rect, squarify
from ui.theme import palette, plain, plain_inline

_GAP = 2.0          # between programs
_MIN_LABEL = 30     # smallest program box that gets an icon


def program_pixmap(program: Program, size: int, ratio: float = 1.0) -> QPixmap | None:
    """The program's icon from the image, scaled, or None when there is none."""
    if not program.icon:
        return None
    image = QImage.fromData(program.icon)
    if image.isNull():
        return None
    pixels = max(1, int(size * ratio))
    scaled = image.scaled(pixels, pixels, Qt.AspectRatioMode.KeepAspectRatio,
                          Qt.TransformationMode.SmoothTransformation)
    pixmap = QPixmap.fromImage(scaled)
    pixmap.setDevicePixelRatio(ratio)
    return pixmap


def monogram(program: Program, size: int, colour: str, ratio: float = 1.0) -> QPixmap:
    """A lettered disc for a program whose icon was not in memory."""
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(255, 255, 255, 225))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(QRectF(0, 0, size, size))
    font = QFont()
    font.setBold(True)
    font.setPixelSize(max(8, int(size * 0.5)))
    painter.setFont(font)
    painter.setPen(QColor(colour).darker(140))
    letter = next((c for c in program.title if c.isalnum()), "?").upper()
    painter.drawText(QRectF(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, letter)
    painter.end()
    return pixmap


class _Tile:
    __slots__ = ("program", "rect", "rank", "processes")

    def __init__(self, program, rect, rank, processes):
        self.program = program
        self.rect = rect
        self.rank = rank
        self.processes = processes          # [(ProcessMemory, Rect)]


class TreemapCanvas(QWidget):
    """The treemap itself. Painted by hand; see core.treemap for the layout."""

    program_selected = pyqtSignal(str)          # program key
    zoom_requested = pyqtSignal(str)            # program key, "" for all
    show_process = pyqtSignal(str)              # PID

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumSize(320, 240)
        self.programs: list[Program] = []
        self.metric = DEFAULT_METRIC
        self.flagged: dict[str, list[str]] = {}
        self.zoom = ""
        self.selected = ""
        self.needle = ""
        self.dark = True
        self.total = 0
        self._ranks: dict[str, int] = {}
        self._tiles: list[_Tile] = []
        self._hover: tuple[_Tile, object, Rect] | None = None
        self._icons: dict[tuple[str, int], QPixmap | None] = {}

    # ── Data ──────────────────────────────────────────────────────────────────

    def set_data(self, programs: list[Program], metric: str,
                 flagged: dict[str, list[str]] | None = None):
        self.programs = ranked(programs, metric)
        self.metric = metric
        self.flagged = flagged or {}
        self.total = sum(p.total(metric) for p in self.programs)
        self._ranks = {p.key: i for i, p in enumerate(self.programs)}
        if self.zoom and self.zoom not in self._ranks:
            self.zoom = ""
        self._icons.clear()
        self._relayout()

    def set_zoom(self, key: str):
        self.zoom = key if key in self._ranks else ""
        self._relayout()

    def select(self, key: str):
        self.selected = key
        self.update()

    def set_needle(self, text: str):
        self.needle = text.strip().lower()
        self.update()

    def set_dark(self, dark: bool):
        self.dark = dark
        self.update()

    def program(self, key: str) -> Program | None:
        rank = self._ranks.get(key)
        return None if rank is None else self.programs[rank]

    def matches(self, program: Program) -> bool:
        if not self.needle:
            return True
        hay = " ".join([program.title, program.name, program.path]
                       + [p.pid for p in program.processes]).lower()
        return self.needle in hay

    # ── Layout ────────────────────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._relayout()

    def _relayout(self):
        area = Rect(0, 0, float(self.width()), float(self.height()))
        self._hover = None
        self._tiles = []
        shown = [self.program(self.zoom)] if self.zoom else self.programs
        if not shown:
            self.update()
            return
        rects = squarify([p.total(self.metric) for p in shown], area)
        for program, rect in zip(shown, rects, strict=True):
            if rect.w < 1 or rect.h < 1:
                continue
            inner = rect.inset(_GAP / 2)
            values = [proc.value(self.metric) for proc in program.processes]
            boxes = squarify(values, inner)
            self._tiles.append(_Tile(program, rect, self._ranks[program.key],
                                     list(zip(program.processes, boxes, strict=True))))
        self.update()

    def hit(self, x: float, y: float):
        """(tile, process, process rect) under a point, or None."""
        for tile in self._tiles:
            if not tile.rect.contains(x, y):
                continue
            for proc, box in tile.processes:
                if box.contains(x, y):
                    return tile, proc, box
            return tile, None, tile.rect
        return None

    # ── Painting ──────────────────────────────────────────────────────────────

    def _icon(self, program: Program, size: int) -> QPixmap:
        key = (program.key, size)
        if key not in self._icons:
            ratio = self.devicePixelRatioF() or 1.0
            self._icons[key] = program_pixmap(program, size, ratio) or monogram(
                program, size, colour_for(self._ranks.get(program.key, 99)), ratio)
        return self._icons[key]

    def paintEvent(self, _event):
        tokens = palette(self.dark)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.fillRect(self.rect(), QColor(tokens["bg"]))
        if not self._tiles:
            painter.end()
            return
        danger = QColor(tokens["danger"])
        for tile in self._tiles:
            base = QColor(colour_for(tile.rank))
            dimmed = not self.matches(tile.program)
            for index, (proc, box) in enumerate(tile.processes):
                if box.w < 0.6 or box.h < 0.6:
                    continue
                rect = QRectF(box.x, box.y, box.w, box.h)
                shade = base.lighter(100 + (index % 4) * 5)
                # A soft cushion, so neighbouring boxes of one program read
                # as separate without hard borders everywhere.
                gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
                gradient.setColorAt(0.0, shade.lighter(118))
                gradient.setColorAt(1.0, shade.darker(118))
                painter.fillRect(rect, QBrush(gradient))
                if box.w > 3 and box.h > 3:
                    painter.setPen(QPen(base.darker(150), 1))
                    painter.drawRect(rect.adjusted(0, 0, -1, -1))
                if proc.pid in self.flagged and box.w > 8 and box.h > 8:
                    corner = QPainterPath()
                    right, top = rect.right(), rect.top()
                    size = min(12.0, box.w / 2, box.h / 2)
                    corner.moveTo(right - size, top)
                    corner.lineTo(right, top)
                    corner.lineTo(right, top + size)
                    corner.closeSubpath()
                    painter.fillPath(corner, danger)
            if dimmed:
                painter.fillRect(QRectF(tile.rect.x, tile.rect.y, tile.rect.w, tile.rect.h),
                                 QColor(0, 0, 0, 165))

        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        for tile in self._tiles:
            if self.matches(tile.program):
                self._paint_label(painter, tile)

        # Selection and hover outlines on top of everything.
        if self.selected:
            for tile in self._tiles:
                if tile.program.key == self.selected:
                    painter.setPen(QPen(QColor(tokens["accent"]), 2.5))
                    painter.setBrush(Qt.BrushStyle.NoBrush)
                    r = tile.rect
                    painter.drawRect(QRectF(r.x + 1.25, r.y + 1.25, r.w - 2.5, r.h - 2.5))
        if self._hover is not None:
            tile, _proc, box = self._hover
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor(255, 255, 255, 150), 1.5))
            r = tile.rect
            painter.drawRect(QRectF(r.x + 0.75, r.y + 0.75, r.w - 1.5, r.h - 1.5))
            painter.setPen(QPen(QColor(255, 255, 255), 2))
            painter.drawRect(QRectF(box.x + 1, box.y + 1, box.w - 2, box.h - 2))
        painter.end()

    def _paint_label(self, painter: QPainter, tile: _Tile):
        rect = tile.rect
        side = min(rect.w, rect.h)
        if side < _MIN_LABEL:
            return
        program = tile.program
        icon = int(max(16, min(72, side * 0.4)))
        title_font = QFont(self.font())
        title_font.setBold(True)
        title_font.setPixelSize(13 if side > 160 else 12)
        sub_font = QFont(self.font())
        sub_font.setPixelSize(11)
        has_text = rect.w >= 84 and rect.h >= icon + 44
        block = icon + (36 if has_text else 0)
        cx = rect.x + rect.w / 2
        top = rect.y + (rect.h - block) / 2
        text_w = 0.0
        title = size_text = ""
        if has_text:
            share = program.total(self.metric) / self.total * 100 if self.total else 0
            size_text = f"{format_bytes(program.total(self.metric))}  ·  {share:.0f}%"
            metrics = QFontMetrics(title_font)
            title = metrics.elidedText(program.title, Qt.TextElideMode.ElideRight,
                                       int(rect.w - 16))
            text_w = max(metrics.horizontalAdvance(title),
                         QFontMetrics(sub_font).horizontalAdvance(size_text))
        # A translucent card behind icon and text keeps them legible on any hue.
        card_w = max(icon, text_w) + 18
        card = QRectF(cx - card_w / 2, top - 8, card_w, block + 14)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 70))
        painter.drawRoundedRect(card, 8, 8)
        painter.drawPixmap(QPointF(cx - icon / 2, top), self._icon(program, icon))
        if has_text:
            painter.setPen(QColor(255, 255, 255))
            painter.setFont(title_font)
            painter.drawText(QRectF(rect.x + 4, top + icon + 4, rect.w - 8, 18),
                             Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, title)
            painter.setPen(QColor(255, 255, 255, 215))
            painter.setFont(sub_font)
            painter.drawText(QRectF(rect.x + 4, top + icon + 21, rect.w - 8, 16),
                             Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
                             size_text)

    # ── Interaction ───────────────────────────────────────────────────────────

    def tooltip_html(self, tile: _Tile, proc) -> str:
        """Rich text, but every value from the image goes through plain_inline()."""
        program = tile.program
        dim = palette(self.dark)["text_dim"]
        total = program.total(self.metric)
        share = total / self.total * 100 if self.total else 0

        def row(label, value):
            return (f"<tr><td style='color:{dim};padding-right:10px'>{label}</td>"
                    f"<td>{value}</td></tr>")

        parts = [f"<b>{plain_inline(program.title)}</b><br>"]
        if program.path:
            parts.append(f"<span style='color:{dim}'>{plain_inline(program.path)}</span>")
        rows = []
        if proc is not None:
            rows.append(row("Process", f"{plain_inline(proc.name)} (PID {plain_inline(proc.pid)}, "
                                       f"parent {plain_inline(proc.ppid or '?')})"))
            for metric, label, _ in METRICS:
                if metric in proc.values:
                    value = format_bytes(proc.values[metric])
                    rows.append(row(label, f"<b>{value}</b>" if metric == self.metric else value))
            if proc.threads:
                rows.append(row("Threads", plain_inline(proc.threads)))
            if proc.created:
                rows.append(row("Started", plain_inline(proc.created)))
        rows.append(row("Program total",
                        f"{format_bytes(total)} in {len(program.processes)} "
                        f"process{'es' if len(program.processes) != 1 else ''} "
                        f"({share:.1f}% of {METRIC_LABELS[self.metric].lower()})"))
        parts.append("<table>" + "".join(rows) + "</table>")
        if proc is not None and proc.pid in self.flagged:
            danger = palette(self.dark)["danger"]
            parts.append(f"<span style='color:{danger}'><b>Flagged by Insights:</b></span> "
                         + "; ".join(plain_inline(t) for t in self.flagged[proc.pid]))
        return "".join(parts)

    def mouseMoveEvent(self, event):
        found = self.hit(event.position().x(), event.position().y())
        previous = self._hover
        self._hover = found
        if found is None:
            QToolTip.hideText()
        elif previous is None or previous[1] is not found[1] or previous[0] is not found[0]:
            tile, proc, _ = found
            QToolTip.showText(event.globalPosition().toPoint(),
                              self.tooltip_html(tile, proc), self)
        if previous != found:
            self.update()

    def leaveEvent(self, event):
        self._hover = None
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        found = self.hit(event.position().x(), event.position().y())
        if event.button() == Qt.MouseButton.LeftButton and found:
            self.select(found[0].program.key)
            self.program_selected.emit(found[0].program.key)

    def mouseDoubleClickEvent(self, event):
        found = self.hit(event.position().x(), event.position().y())
        if self.zoom:
            self.zoom_requested.emit("")
        elif found:
            self.zoom_requested.emit(found[0].program.key)

    def contextMenuEvent(self, event):
        found = self.hit(event.pos().x(), event.pos().y())
        if not found:
            return
        tile, proc, _ = found
        menu = QMenu(self)
        if self.zoom:
            menu.addAction("Show All Programs", lambda: self.zoom_requested.emit(""))
        else:
            menu.addAction(f"Zoom Into {tile.program.title}",
                           lambda: self.zoom_requested.emit(tile.program.key))
        if proc is not None:
            menu.addAction(f"Show PID {proc.pid} in Process List",
                           lambda: self.show_process.emit(proc.pid))
        if tile.program.path:
            from PyQt6.QtWidgets import QApplication
            menu.addAction("Copy Path",
                           lambda: QApplication.clipboard().setText(tile.program.path))
        menu.exec(event.globalPos())


class MemoryUsageView(QWidget):
    """The tab: header, controls, the map and the ranked program list."""

    collect_requested = pyqtSignal(list)
    show_process = pyqtSignal(str)                  # PID

    def __init__(self, parent=None):
        super().__init__(parent)
        self.programs: list[Program] = []
        self.flagged: dict[str, list[str]] = {}
        self.metric = DEFAULT_METRIC
        self.dark = True
        self._build()
        self._refresh()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        title = QLabel("Memory Usage")
        title.setObjectName("overviewTitle")
        self.summary_lbl = QLabel("")
        self.summary_lbl.setObjectName("overviewBlurb")
        self.summary_lbl.setWordWrap(True)
        titles.addWidget(title)
        titles.addWidget(self.summary_lbl)
        header.addLayout(titles, 1)
        self.collect_btn = QPushButton("Collect Memory Usage")
        self.collect_btn.setObjectName("primaryButton")
        self.collect_btn.setToolTip("Run DumpScope's memory usage plugin on this image. "
                                    "It takes a few seconds.")
        self.collect_btn.clicked.connect(lambda: self.collect_requested.emit([MEMORY_PLUGIN]))
        header.addWidget(self.collect_btn, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        controls.addWidget(QLabel("Size boxes by"))
        self.metric_box = QComboBox()
        for key, label, explanation in METRICS:
            self.metric_box.addItem(label, key)
            self.metric_box.setItemData(self.metric_box.count() - 1, explanation,
                                        Qt.ItemDataRole.ToolTipRole)
        self.metric_box.currentIndexChanged.connect(self._metric_changed)
        controls.addWidget(self.metric_box)
        self.back_btn = QPushButton("All Programs")
        self.back_btn.setToolTip("Zoom back out (or double-click the map)")
        self.back_btn.clicked.connect(lambda: self.zoom_to(""))
        controls.addWidget(self.back_btn)
        self.crumb_lbl = QLabel("")
        self.crumb_lbl.setObjectName("overviewBlurb")
        controls.addWidget(self.crumb_lbl)
        controls.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Highlight program, path or PID")
        self.search.setClearButtonEnabled(True)
        self.search.setMaximumWidth(280)
        self.search.textChanged.connect(self._search)
        controls.addWidget(self.search, 1)
        self.export_btn = QPushButton("Export PNG…")
        self.export_btn.clicked.connect(self._export)
        controls.addWidget(self.export_btn)
        layout.addLayout(controls)

        self.help_lbl = QLabel("")
        self.help_lbl.setObjectName("overviewBlurb")
        self.help_lbl.setWordWrap(True)
        layout.addWidget(self.help_lbl)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        empty = QFrame()
        empty.setObjectName("launcherEmpty")
        empty_layout = QVBoxLayout(empty)
        empty_layout.addStretch()
        heading = QLabel("No memory usage yet")
        heading.setObjectName("launcherEmptyTitle")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text = QLabel(
            "See which programs held the machine's memory when the image was taken, "
            "like a disk usage map: one box per process, sized by its memory, "
            "grouped by program with the program's own icon. Windows images only.")
        text.setObjectName("launcherEmptyText")
        text.setWordWrap(True)
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button = QPushButton("Collect Memory Usage")
        button.setObjectName("primaryButton")
        button.clicked.connect(lambda: self.collect_requested.emit([MEMORY_PLUGIN]))
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(button)
        row.addStretch()
        empty_layout.addWidget(heading)
        empty_layout.addWidget(text)
        empty_layout.addSpacing(8)
        empty_layout.addLayout(row)
        empty_layout.addStretch()
        self.stack.addWidget(empty)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.canvas = TreemapCanvas()
        self.canvas.program_selected.connect(self._select_in_list)
        self.canvas.zoom_requested.connect(self.zoom_to)
        self.canvas.show_process.connect(self.show_process)
        split.addWidget(self.canvas)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Program", "Memory", "Share", "Processes"])
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header_view = self.tree.header()
        header_view.setStretchLastSection(False)
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            header_view.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.currentItemChanged.connect(self._list_selected)
        self.tree.itemDoubleClicked.connect(self._list_activated)
        split.addWidget(self.tree)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setSizes([900, 360])
        self.stack.addWidget(split)

    # ── Data ──────────────────────────────────────────────────────────────────

    def set_dark(self, dark: bool):
        self.dark = dark
        self.canvas.set_dark(dark)

    def set_programs(self, programs: list[Program] | None,
                     flagged: dict[str, list[str]] | None = None):
        """`flagged` maps a PID to the titles of the Insights findings on it."""
        self.programs = programs or []
        self.flagged = flagged or {}
        self._refresh()

    def _metric_changed(self, index: int):
        self.metric = self.metric_box.itemData(index) or DEFAULT_METRIC
        self._refresh()

    def _refresh(self):
        has_data = bool(ranked(self.programs, self.metric))
        self.stack.setCurrentIndex(1 if has_data else 0)
        self.collect_btn.setVisible(not self.programs)
        for widget in (self.metric_box, self.search, self.export_btn):
            widget.setEnabled(has_data)
        self.canvas.set_data(self.programs, self.metric, self.flagged)
        self._fill_list()
        self._update_texts()

    def _update_texts(self):
        explanation = dict((k, e) for k, _, e in METRICS)[self.metric]
        label = METRIC_LABELS[self.metric].lower()
        self.help_lbl.setText(
            f"Each box is one process, sized by its {label}: {explanation} "
            "Boxes are grouped by program, with the program's icon in the middle. "
            "Hover for details, double-click a program to zoom in. A red corner "
            "marks a process that Insights flagged.")
        shown = self.canvas.programs
        if not shown:
            self.summary_lbl.setText(
                "Not collected for this image yet." if not self.programs else
                f"No process reports any {label}.")
        else:
            processes = sum(len(p.processes) for p in shown)
            top = shown[0]
            self.summary_lbl.setText(
                f"{format_bytes(self.canvas.total)} of {label} across {processes} "
                f"processes in {len(shown)} programs. Largest: {top.title}, "
                f"{format_bytes(top.total(self.metric))} in {len(top.processes)} "
                f"process{'es' if len(top.processes) != 1 else ''}.")
        zoomed = self.canvas.program(self.canvas.zoom) if self.canvas.zoom else None
        self.back_btn.setVisible(zoomed is not None)
        self.crumb_lbl.setText(f"› {zoomed.title}" if zoomed else "")

    def _fill_list(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        total = self.canvas.total or 1
        ratio = self.devicePixelRatioF() or 1.0
        for rank, program in enumerate(self.canvas.programs):
            amount = program.total(self.metric)
            item = QTreeWidgetItem([
                program.title, format_bytes(amount), f"{amount / total * 100:.1f}%",
                str(len(program.processes))])
            item.setData(0, Qt.ItemDataRole.UserRole, program.key)
            item.setToolTip(0, plain(program.path or program.name))
            pixmap = program_pixmap(program, 16, ratio) or monogram(
                program, 16, colour_for(rank), ratio)
            item.setIcon(0, QIcon(pixmap))
            for column in (1, 2, 3):
                item.setTextAlignment(column, Qt.AlignmentFlag.AlignRight
                                      | Qt.AlignmentFlag.AlignVCenter)
            for proc in program.processes:
                child = QTreeWidgetItem([
                    f"{proc.name}  (PID {proc.pid})",
                    format_bytes(proc.value(self.metric)), "", ""])
                child.setData(0, Qt.ItemDataRole.UserRole, program.key)
                child.setTextAlignment(1, Qt.AlignmentFlag.AlignRight
                                       | Qt.AlignmentFlag.AlignVCenter)
                if proc.pid in self.flagged:
                    child.setForeground(0, QColor(palette(self.dark)["danger"]))
                    child.setToolTip(0, plain("; ".join(self.flagged[proc.pid])))
                item.addChild(child)
            self.tree.addTopLevelItem(item)
        self.tree.blockSignals(False)

    # ── Interaction ───────────────────────────────────────────────────────────

    def zoom_to(self, key: str):
        self.canvas.set_zoom(key)
        self._update_texts()

    def _search(self, text: str):
        self.canvas.set_needle(text)

    def _select_in_list(self, key: str):
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item.data(0, Qt.ItemDataRole.UserRole) == key:
                self.tree.blockSignals(True)
                self.tree.setCurrentItem(item)
                self.tree.scrollToItem(item)
                self.tree.blockSignals(False)
                return

    def _list_selected(self, current, _previous):
        if current is not None:
            self.canvas.select(current.data(0, Qt.ItemDataRole.UserRole))

    def _list_activated(self, item, _column):
        key = item.data(0, Qt.ItemDataRole.UserRole)
        if item.parent() is not None:
            pid = item.text(0).rsplit("PID ", 1)[-1].rstrip(")")
            self.show_process.emit(pid)
        elif key:
            self.zoom_to("" if self.canvas.zoom == key else key)

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Memory Map", "memory-usage.png",
                                              "PNG image (*.png)")
        if path:
            self.canvas.grab().save(path, "PNG")
