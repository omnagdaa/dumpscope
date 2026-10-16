"""
The case explorer: everything the case holds, in one tree.

Three groups, the way an analyst thinks about a case:

    Data Sources   the images under examination
    Results        every plugin run that was saved, reopenable without rerunning
    Bookmarks      tagged findings

Reopening a stored result matters more than it sounds: a filescan over a large
image can take many minutes, and before this the only way back to its output
was to run it again.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from ui.theme import palette
from PyQt6.QtWidgets import (
    QAbstractItemView, QMenu, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

# Item roles: what kind of node this is, and the id it refers to.
NODE_KIND = Qt.ItemDataRole.UserRole
NODE_ID = Qt.ItemDataRole.UserRole + 1
NODE_PAYLOAD = Qt.ItemDataRole.UserRole + 2

KIND_GROUP = "group"
KIND_SOURCE = "source"
KIND_RESULT = "result"
KIND_BOOKMARK = "bookmark"


def _format_size(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024:
            return f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} PB"


class CaseTree(QWidget):
    """Navigator for one case. Emits what the window should act on."""

    source_activated   = pyqtSignal(int, str)   # source id, path
    source_remove      = pyqtSignal(int)
    source_hash        = pyqtSignal(int, str)   # source id, path
    add_source         = pyqtSignal()
    result_opened      = pyqtSignal(int)        # stored result id
    result_deleted     = pyqtSignal(int)
    bookmark_activated = pyqtSignal(dict)
    bookmark_deleted   = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._active_source_id: int | None = None
        # Plugin id -> the name the ribbon and tabs use. The window sets it from
        # the registry so "Process List" is not "PsList" here.
        self.plugin_name = lambda plugin_id: plugin_id.rsplit(".", 1)[-1]
        # Placeholder rows are painted with a brush, not a stylesheet, so the
        # colour has to be read out of the palette rather than declared in QSS.
        self._faint = QColor(palette(dark=True)["text_faint"])
        self._danger = QColor(palette(dark=True)["danger"])
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tree = QTreeWidget()
        self.tree.setObjectName("caseTree")
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(14)
        self.tree.setAnimated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        self.tree.itemDoubleClicked.connect(self._activate)
        layout.addWidget(self.tree)

        self.sources_group = self._group("Data Sources")
        self.results_group = self._group("Results")
        self.bookmarks_group = self._group("Bookmarks")

    def _group(self, title: str) -> QTreeWidgetItem:
        item = QTreeWidgetItem(self.tree, [title])
        item.setData(0, NODE_KIND, KIND_GROUP)
        font = item.font(0)
        font.setBold(True)
        font.setPointSize(max(8, font.pointSize() - 1))
        item.setFont(0, font)
        item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        item.setExpanded(True)
        return item

    # ── Population ────────────────────────────────────────────────────────────

    def refresh(self, sources: list[dict], results: list[dict],
                bookmarks: list[dict], active_source_id: int | None = None):
        self._active_source_id = active_source_id
        # Keyed by the item, not its text: the text carries a count, so a new
        # result would otherwise reopen a group the examiner had collapsed.
        groups = (self.sources_group, self.results_group, self.bookmarks_group)
        expanded = {id(group): group.isExpanded() for group in groups}
        self._fill_sources(sources)
        self._fill_results(results)
        self._fill_bookmarks(bookmarks)
        for group in groups:
            group.setExpanded(expanded[id(group)])

    @staticmethod
    def _clear(group: QTreeWidgetItem):
        group.takeChildren()

    def _fill_sources(self, sources: list[dict]):
        self._clear(self.sources_group)
        self.sources_group.setText(0, f"Data Sources  ({len(sources)})")
        for source in sources:
            name = source.get("display_name") or os.path.basename(source["path"])
            item = QTreeWidgetItem(self.sources_group, [name])
            item.setData(0, NODE_KIND, KIND_SOURCE)
            item.setData(0, NODE_ID, source["id"])
            item.setData(0, NODE_PAYLOAD, source)

            missing = not os.path.exists(source["path"])
            details = [_format_size(source.get("size_bytes") or 0)]
            if source.get("os_hint"):
                details.append(source["os_hint"])
            if source.get("md5"):
                details.append("hashed")
            if missing:
                details.append("FILE MISSING")
            item.setToolTip(0, source["path"] + "\n" + " · ".join(details))

            if missing:
                item.setForeground(0, QBrush(self._danger))
            if source["id"] == self._active_source_id:
                font = item.font(0)
                font.setBold(True)
                item.setFont(0, font)
                item.setText(0, f"{name}  (active)")

        if not sources:
            placeholder = QTreeWidgetItem(self.sources_group, ["No image loaded"])
            placeholder.setFlags(Qt.ItemFlag.ItemIsEnabled)
            placeholder.setForeground(0, QBrush(self._faint))

    def _fill_results(self, results: list[dict]):
        self._clear(self.results_group)
        self.results_group.setText(0, f"Results  ({len(results)})")
        for result in results:
            plugin = self.plugin_name(result["plugin"])
            rows = result.get("row_count") or 0
            noun = "row" if rows == 1 else "rows"
            item = QTreeWidgetItem(self.results_group, [f"{plugin}   {rows:,} {noun}"])
            item.setData(0, NODE_KIND, KIND_RESULT)
            item.setData(0, NODE_ID, result["id"])
            item.setData(0, NODE_PAYLOAD, result)
            tooltip = [result["plugin"], f"{rows:,} {noun}"]
            if result.get("source_name"):
                tooltip.append(f"from {result['source_name']}")
            if result.get("created_at"):
                tooltip.append(result["created_at"])
            item.setToolTip(0, "\n".join(tooltip))

        if not results:
            placeholder = QTreeWidgetItem(self.results_group, ["Nothing saved yet"])
            placeholder.setFlags(Qt.ItemFlag.ItemIsEnabled)
            placeholder.setForeground(0, QBrush(self._faint))

    def _fill_bookmarks(self, bookmarks: list[dict]):
        self._clear(self.bookmarks_group)
        self.bookmarks_group.setText(0, f"Bookmarks  ({len(bookmarks)})")
        for bookmark in bookmarks:
            label = bookmark.get("label") or "(unlabelled)"
            tag = bookmark.get("tag") or ""
            item = QTreeWidgetItem(
                self.bookmarks_group, [f"{label}   {tag}" if tag else label]
            )
            item.setData(0, NODE_KIND, KIND_BOOKMARK)
            item.setData(0, NODE_ID, bookmark["id"])
            item.setData(0, NODE_PAYLOAD, bookmark)
            if bookmark.get("tag_color"):
                item.setForeground(0, QBrush(QColor(bookmark["tag_color"])))
            tooltip = [bookmark.get("artifact_type") or ""]
            if bookmark.get("notes"):
                tooltip.append(bookmark["notes"])
            if bookmark.get("description"):
                tooltip.append(bookmark["description"])
            item.setToolTip(0, "\n".join(t for t in tooltip if t))

        if not bookmarks:
            placeholder = QTreeWidgetItem(self.bookmarks_group, ["No bookmarks"])
            placeholder.setFlags(Qt.ItemFlag.ItemIsEnabled)
            placeholder.setForeground(0, QBrush(self._faint))

    def apply_theme(self, dark: bool):
        """Follow the application palette for the item colours QSS cannot reach."""
        self._faint = QColor(palette(dark=dark)["text_faint"])
        self._danger = QColor(palette(dark=dark)["danger"])

    # ── Interaction ───────────────────────────────────────────────────────────

    def _activate(self, item: QTreeWidgetItem, _column: int = 0):
        kind = item.data(0, NODE_KIND)
        payload = item.data(0, NODE_PAYLOAD)
        if kind == KIND_SOURCE:
            self.source_activated.emit(item.data(0, NODE_ID), payload["path"])
        elif kind == KIND_RESULT:
            self.result_opened.emit(item.data(0, NODE_ID))
        elif kind == KIND_BOOKMARK:
            self.bookmark_activated.emit(payload)

    def _context_menu(self, point):
        item = self.tree.itemAt(point)
        menu = QMenu(self)
        kind = item.data(0, NODE_KIND) if item else None

        if kind == KIND_SOURCE:
            payload = item.data(0, NODE_PAYLOAD)
            source_id = item.data(0, NODE_ID)
            menu.addAction("Make Active", lambda: self.source_activated.emit(
                source_id, payload["path"]))
            menu.addAction("Verify Hashes", lambda: self.source_hash.emit(
                source_id, payload["path"]))
            menu.addSeparator()
            menu.addAction("Remove from Case",
                           lambda: self.source_remove.emit(source_id))
        elif kind == KIND_RESULT:
            result_id = item.data(0, NODE_ID)
            menu.addAction("Open", lambda: self.result_opened.emit(result_id))
            menu.addSeparator()
            menu.addAction("Delete", lambda: self.result_deleted.emit(result_id))
        elif kind == KIND_BOOKMARK:
            bookmark_id = item.data(0, NODE_ID)
            payload = item.data(0, NODE_PAYLOAD)
            menu.addAction("Show", lambda: self.bookmark_activated.emit(payload))
            menu.addSeparator()
            menu.addAction("Delete", lambda: self.bookmark_deleted.emit(bookmark_id))
        else:
            menu.addAction("Add Data Source…", self.add_source.emit)

        if not menu.isEmpty():
            menu.exec(self.tree.viewport().mapToGlobal(point))
