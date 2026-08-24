"""
The tag manager.

Tags are the examiner's own vocabulary for an image — suspicious, malicious,
known-good — and the panel is the index built out of them: every tag lists the
output lines it has been applied to, and activating one navigates back to that
line in the plugin it came from.

A tag applied to a row stores the row's full {column: value} mapping rather
than its position. Row indices are meaningless the moment the table is sorted
or the plugin is re-run, and a forensic note that silently points at the wrong
line is worse than no note.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QLabel, QMenu, QPushButton, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ui import icons
from ui.theme import palette

NODE_KIND = Qt.ItemDataRole.UserRole + 1
NODE_NAME = Qt.ItemDataRole.UserRole + 2
NODE_PAYLOAD = Qt.ItemDataRole.UserRole + 3

KIND_TAG = "tag"
KIND_FINDING = "finding"
KIND_EMPTY = "empty"


class TagPanel(QWidget):
    """A tag tree with its findings underneath."""

    tag_created   = pyqtSignal()
    tag_renamed   = pyqtSignal(str)          # the tag to rename
    tag_recoloured = pyqtSignal(str)         # the tag to recolour
    tag_deleted   = pyqtSignal(str)          # the tag to delete
    finding_activated = pyqtSignal(dict)
    finding_deleted   = pyqtSignal(int)
    finding_untagged  = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("tagPanel")
        self._dark = True
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("dockHeader")
        header.setFixedHeight(28)
        bar = QHBoxLayout(header)
        bar.setContentsMargins(10, 0, 6, 0)
        bar.setSpacing(4)

        title = QLabel("TAGS")
        title.setObjectName("dockHeading")

        self.add_btn = QPushButton("+")
        self.add_btn.setObjectName("iconButton")
        self.add_btn.setFixedSize(20, 20)
        self.add_btn.setToolTip("New tag")
        self.add_btn.clicked.connect(self.tag_created)

        bar.addWidget(title)
        bar.addStretch()
        bar.addWidget(self.add_btn)
        layout.addWidget(header)

        self.tree = QTreeWidget()
        self.tree.setObjectName("tagTree")
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(12)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        self.tree.itemActivated.connect(self._activate)
        self.tree.itemDoubleClicked.connect(self._activate)
        layout.addWidget(self.tree, 1)

    # ── Population ────────────────────────────────────────────────────────────

    def apply_theme(self, dark: bool):
        self._dark = dark

    def refresh(self, tags: list[dict], findings: list[dict]):
        """
        Rebuild from the case's tags and every tagged finding.

        Expansion state is preserved, so refreshing after a tag is applied does
        not collapse the tree the examiner is working in.
        """
        expanded = {
            self.tree.topLevelItem(i).data(0, NODE_NAME)
            for i in range(self.tree.topLevelItemCount())
            if self.tree.topLevelItem(i).isExpanded()
        }
        selected = self.tree.currentItem()
        selected_id = selected.data(0, NODE_PAYLOAD) if selected else None

        self.tree.clear()
        by_tag: dict[str, list[dict]] = {}
        for finding in findings:
            name = (finding.get("tag") or "").strip()
            if name:
                by_tag.setdefault(name, []).append(finding)

        faint = QColor(palette(dark=self._dark)["text_faint"])

        for tag in tags:
            name = tag["name"]
            mine = by_tag.pop(name, [])
            item = QTreeWidgetItem(self.tree, [f"{name}   {len(mine)}"])
            item.setData(0, NODE_KIND, KIND_TAG)
            item.setData(0, NODE_NAME, name)
            item.setIcon(0, icons.icon("tag", 13, tag.get("color") or palette()["text_dim"]))
            font = item.font(0)
            font.setBold(True)
            item.setFont(0, font)
            if not mine:
                item.setForeground(0, QBrush(faint))
            self._fill(item, mine)
            if name in expanded or (expanded == set() and mine):
                item.setExpanded(True)

        # A tag can survive on a finding after being deleted from the palette,
        # or arrive from a case file written elsewhere. Show it rather than
        # dropping the finding on the floor.
        for name, mine in by_tag.items():
            item = QTreeWidgetItem(self.tree, [f"{name}   {len(mine)}  (removed)"])
            item.setData(0, NODE_KIND, KIND_TAG)
            item.setData(0, NODE_NAME, name)
            item.setForeground(0, QBrush(faint))
            self._fill(item, mine)

        if not tags:
            placeholder = QTreeWidgetItem(self.tree, ["No tags yet — use + to add one"])
            placeholder.setData(0, NODE_KIND, KIND_EMPTY)
            placeholder.setFlags(Qt.ItemFlag.ItemIsEnabled)
            placeholder.setForeground(0, QBrush(faint))

        if selected_id is not None:
            self._reselect(selected_id)

    def _fill(self, parent: QTreeWidgetItem, findings: list[dict]):
        for finding in findings:
            label = finding.get("label") or "(unlabelled)"
            plugin = (finding.get("artifact_type") or "").rsplit(".", 1)[-1]
            item = QTreeWidgetItem(parent, [f"{label}   ·  {plugin}" if plugin else label])
            item.setData(0, NODE_KIND, KIND_FINDING)
            item.setData(0, NODE_PAYLOAD, finding["id"])
            item.setData(0, NODE_NAME, finding)
            tooltip = [finding.get("artifact_type") or ""]
            if finding.get("cell_column"):
                tooltip.append(f"{finding['cell_column']}: {finding.get('cell_value', '')}")
            if finding.get("notes"):
                tooltip.append(finding["notes"])
            if finding.get("created_at"):
                tooltip.append(f"Added {finding['created_at']}")
            item.setToolTip(0, "\n".join(t for t in tooltip if t))

    def _reselect(self, finding_id):
        """Keep the selection on the same finding across a refresh."""
        for i in range(self.tree.topLevelItemCount()):
            group = self.tree.topLevelItem(i)
            for j in range(group.childCount()):
                child = group.child(j)
                if child.data(0, NODE_PAYLOAD) == finding_id:
                    self.tree.setCurrentItem(child)
                    return

    # ── Interaction ───────────────────────────────────────────────────────────

    def _activate(self, item: QTreeWidgetItem, _column: int = 0):
        if item.data(0, NODE_KIND) == KIND_FINDING:
            self.finding_activated.emit(item.data(0, NODE_NAME))

    def _context_menu(self, point):
        item = self.tree.itemAt(point)
        menu = QMenu(self)
        if item is None or item.data(0, NODE_KIND) == KIND_EMPTY:
            menu.addAction("New Tag…", self.tag_created.emit)
        elif item.data(0, NODE_KIND) == KIND_TAG:
            name = item.data(0, NODE_NAME)
            menu.addAction("New Tag…", self.tag_created.emit)
            menu.addSeparator()
            menu.addAction("Rename…", lambda: self.tag_renamed.emit(name))
            menu.addAction("Change Colour…", lambda: self.tag_recoloured.emit(name))
            menu.addAction("Delete Tag…", lambda: self.tag_deleted.emit(name))
        else:
            finding = item.data(0, NODE_NAME)
            menu.addAction("Go to Result", lambda: self.finding_activated.emit(finding))
            menu.addSeparator()
            menu.addAction("Remove Tag",
                           lambda: self.finding_untagged.emit(finding["id"]))
            menu.addAction("Delete Finding",
                           lambda: self.finding_deleted.emit(finding["id"]))
        menu.exec(self.tree.viewport().mapToGlobal(point))
