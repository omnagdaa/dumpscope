"""
Prompt for tagging a finding.

Autopsy's value is not that it can list processes — it is that an examiner can
mark a row, say why it matters, and have that survive into the report. This is
the smallest form of that: a label, a tag from the case's vocabulary, and a
free-text note.
"""

from __future__ import annotations

from PyQt6.QtGui import QColor, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit,
    QPlainTextEdit, QVBoxLayout,
)


class BookmarkDialog(QDialog):
    """Collects label, tag and notes for one bookmarked row."""

    def __init__(self, row: dict, plugin: str, tags: list[dict], parent=None):
        super().__init__(parent)
        self.row = row
        self.plugin = plugin
        self.setWindowTitle("Add Bookmark")
        self.setMinimumWidth(520)
        self._build(tags)

    def _build(self, tags: list[dict]):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(14)

        heading = QLabel(self.plugin)
        heading.setObjectName("dialogHeading")
        layout.addWidget(heading)

        form = QFormLayout()
        form.setSpacing(10)

        self.label_edit = QLineEdit(self._suggested_label())
        self.label_edit.selectAll()

        self.tag_combo = QComboBox()
        self.tag_combo.addItem("(no tag)", "")
        for tag in tags:
            pixmap = QPixmap(12, 12)
            pixmap.fill(QColor(tag.get("color") or "#58a6ff"))
            self.tag_combo.addItem(QIcon(pixmap), tag["name"], tag["name"])

        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setPlaceholderText("Why does this matter?")
        self.notes_edit.setFixedHeight(80)

        form.addRow(QLabel("Label"), self.label_edit)
        form.addRow(QLabel("Tag"), self.tag_combo)
        form.addRow(QLabel("Notes"), self.notes_edit)
        layout.addLayout(form)

        preview = QLabel(self._preview())
        preview.setWordWrap(True)
        preview.setObjectName("dialogBlurb")
        layout.addWidget(preview)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Bookmark")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _suggested_label(self) -> str:
        """
        Name the bookmark after whatever identifies the row to a human.

        Process-shaped output leads with a name, so prefer that over the first
        column, which is usually a PID or an offset.
        """
        for key in ("ImageFileName", "Name", "Process", "Path", "File output",
                    "BaseDllName", "Key", "Variable"):
            value = self.row.get(key)
            if value:
                return str(value)
        for value in self.row.values():
            if value:
                return str(value)
        return self.plugin.rsplit(".", 1)[-1]

    def _preview(self) -> str:
        parts = [f"{key}: {value}" for key, value in self.row.items() if value][:6]
        return "  ·  ".join(parts)

    def values(self) -> dict:
        return {
            "label": self.label_edit.text().strip() or self._suggested_label(),
            "tag": self.tag_combo.currentData() or "",
            "notes": self.notes_edit.toPlainText().strip(),
        }
