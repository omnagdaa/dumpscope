"""
The command palette: everything the application can do, from the keyboard.

A forensics tool accumulates verbs — run one of two hundred plugins, switch the
plugin set to another OS, tag a row, export, re-identify the image. Menus scale
badly past about thirty of those, and a ribbon only shows what fits on one row.
The palette is the flat index over all of it: press Ctrl+Shift+P, type three
letters, press Enter.

Matching is subsequence-based rather than substring, so "psls" finds
``windows.pslist.PsList`` and "tglth" finds Toggle Theme. Results are ranked so
that a match on a word boundary beats a match in the middle of a word, which is
what makes short queries land on the obvious command instead of an alphabetical
accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from PyQt6.QtCore import QEvent, QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout,
    QWidget,
)

from ui import icons

_MAX_RESULTS = 200


@dataclass
class Command:
    """One thing the palette can run."""
    title: str
    run: Callable[[], None]
    subtitle: str = ""
    group: str = ""
    shortcut: str = ""
    glyph: str = "chevron"
    keywords: str = ""

    @property
    def haystack(self) -> str:
        return f"{self.group} {self.title} {self.subtitle} {self.keywords}".lower()


def score(needle: str, command: Command) -> int | None:
    """
    How well `needle` matches, higher being better. None when it does not.

    The title is matched on its own first: a query that matches the title is
    always a better answer than one that only matches a description, however
    tightly it matches the description.
    """
    if not needle:
        return 0
    title = command.title.lower()
    best = _subsequence_score(needle, title)
    if best is not None:
        return best + 1000
    return _subsequence_score(needle, command.haystack)


def _subsequence_score(needle: str, hay: str) -> int | None:
    position = 0
    total = 0
    for character in needle:
        if character == " ":
            continue
        found = hay.find(character, position)
        if found < 0:
            return None
        # A character starting a word is worth far more than one buried in the
        # middle of one; consecutive characters are worth more than scattered.
        if found == 0 or hay[found - 1] in " ._-/":
            total += 12
        elif found == position:
            total += 6
        else:
            total += 1
        total -= min(found - position, 8)
        position = found + 1
    return total


class CommandPalette(QDialog):
    """A filtered list of commands. Closes on Escape, runs one on Enter."""

    chosen = pyqtSignal(object)

    def __init__(self, commands: list[Command], parent=None, is_dark: bool = True):
        super().__init__(parent)
        self.setObjectName("commandPalette")
        self.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint
        )
        self.setModal(True)
        self._commands = commands
        self._is_dark = is_dark
        self._shown: list[Command] = []
        self._build()
        self._apply_filter("")

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(1, 1, 1, 1)
        layout.setSpacing(0)

        self.input = QLineEdit()
        self.input.setObjectName("paletteInput")
        self.input.setPlaceholderText("Type a command or a plugin name…")
        self.input.setFixedHeight(38)
        self.input.textChanged.connect(self._apply_filter)
        self.input.returnPressed.connect(self._activate_current)
        self.input.installEventFilter(self)

        self.list = QListWidget()
        self.list.setObjectName("paletteList")
        self.list.setUniformItemSizes(True)
        self.list.itemActivated.connect(lambda _: self._activate_current())
        self.list.itemClicked.connect(lambda _: self._activate_current())

        self.empty = QLabel("No matching command.")
        self.empty.setObjectName("paletteEmpty")
        self.empty.setVisible(False)

        layout.addWidget(self.input)
        layout.addWidget(self.list, 1)
        layout.addWidget(self.empty)
        self.resize(680, 420)

    # ── Filtering ─────────────────────────────────────────────────────────────

    def _apply_filter(self, text: str):
        needle = text.strip().lower()
        ranked: list[tuple[int, int, Command]] = []
        for index, command in enumerate(self._commands):
            value = score(needle, command)
            if value is not None:
                # `index` keeps the caller's ordering as the tiebreak, so an
                # empty query shows the list as it was handed over.
                ranked.append((-value, index, command))
        ranked.sort()

        self._shown = [command for _score, _index, command in ranked[:_MAX_RESULTS]]
        self.list.clear()
        colour = _dim(self._is_dark)
        for command in self._shown:
            label = command.title
            if command.group:
                label = f"{command.group}: {command.title}"
            item = QListWidgetItem(label)
            if command.subtitle:
                item.setToolTip(command.subtitle)
            if command.shortcut:
                item.setText(f"{label} · {command.shortcut}")
            item.setIcon(icons.icon(command.glyph, size=15, color=colour))
            item.setSizeHint(QSize(0, 28))
            self.list.addItem(item)

        if self._shown:
            self.list.setCurrentRow(0)
        self.list.setVisible(bool(self._shown))
        self.empty.setVisible(not self._shown)

    # ── Keyboard ──────────────────────────────────────────────────────────────

    def eventFilter(self, watched, event):
        """Let the arrow keys drive the list while the caret stays in the box."""
        if watched is self.input and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            if key in (Qt.Key.Key_Down, Qt.Key.Key_Up,
                       Qt.Key.Key_PageDown, Qt.Key.Key_PageUp):
                self.list.keyPressEvent(event)
                return True
        return super().eventFilter(watched, event)

    def _activate_current(self):
        row = self.list.currentRow()
        if not (0 <= row < len(self._shown)):
            return
        command = self._shown[row]
        # Close first: a command that opens a dialog of its own must not do it
        # underneath this one.
        self.accept()
        self.chosen.emit(command)
        command.run()

    def showEvent(self, event):
        super().showEvent(event)
        parent = self.parentWidget()
        if parent is not None:
            centre = parent.geometry().center()
            self.move(centre.x() - self.width() // 2,
                      parent.geometry().top() + 84)
        self.input.setFocus()
        self.input.selectAll()


def _dim(is_dark: bool) -> str:
    from ui.theme import palette
    return palette(dark=is_dark)["text_dim"]
