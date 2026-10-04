"""
The plugin ribbon: every module that can be run against the loaded image,
grouped by category and scoped to the image's operating system.

It was previously built inline in MainWindow and torn down and rebuilt from
scratch whenever the OS changed, which meant every tile — and the state of any
run in flight — was destroyed along with it. Here the tiles are built once per
OS and shown or hidden by the filter, so a running plugin keeps its badge while
the examiner searches for the next one.

The search box is the reason this exists as its own widget. Volatility3 ships
around fifty Windows plugins; a wall of fifty near-identical emoji tiles is a
worse way to find `malfind` than simply typing it.
"""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QScrollArea,
    QSizePolicy, QVBoxLayout, QWidget,
)

from core.plugins import PluginInfo, PluginRegistry
from ui import icons

# Tall enough for the tiles plus the horizontal scrollbar underneath them;
# too short and the scrollbar sits on top of the bottom row of labels.
_COMPACT_HEIGHT = 128
_COMFORTABLE_HEIGHT = 166


class PluginRibbon(QWidget):
    """Emits a plugin id when one of its tiles is clicked."""

    plugin_clicked = pyqtSignal(str)
    theme_toggled = pyqtSignal()
    palette_requested = pyqtSignal()

    def __init__(self, registry: PluginRegistry, compact: bool = True, parent=None):
        super().__init__(parent)
        self.setObjectName("pluginRibbon")
        self.registry = registry
        self._compact = compact
        self._os = ""
        self._buttons: dict[str, "PluginButton"] = {}
        self._groups: list[tuple[str, QWidget, list[str]]] = []
        self._dividers: list[QWidget] = []
        self._icon_buttons: list[QPushButton] = []
        self._is_dark = True
        self._build()
        self._paint_icon_buttons()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.inner = QWidget()
        self.inner.setObjectName("ribbonInner")
        self.row = QHBoxLayout(self.inner)
        self.row.setContentsMargins(14, 4, 14, 6)
        self.row.setSpacing(0)
        self.row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.empty_lbl = QLabel("No plugin matches that search.")
        self.empty_lbl.setObjectName("ribbonEmpty")
        self.empty_lbl.setVisible(False)
        self.row.addWidget(self.empty_lbl)

        self.scroll.setWidget(self.inner)
        outer.addWidget(self.scroll, 1)
        self._apply_height()

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("ribbonHeader")
        header.setFixedHeight(32)
        bar = QHBoxLayout(header)
        bar.setContentsMargins(14, 0, 10, 0)
        bar.setSpacing(6)

        self.scope_lbl = QLabel("No image loaded")
        self.scope_lbl.setObjectName("ribbonHeading")

        self.search = QLineEdit()
        self.search.setObjectName("pluginSearch")
        self.search.setPlaceholderText("Search plugins…  (Ctrl+P)")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(230)
        self.search.setFixedHeight(24)
        self.search.textChanged.connect(self._apply_filter)

        # The density toggle is gone: the tiles are compact by default and the
        # glyphs are vectors, so there is nothing a "large" mode reveals that
        # the compact one hides.
        self.palette_btn = self._icon_button(
            "command", "All commands  (Ctrl+Shift+P)")
        self.palette_btn.clicked.connect(self.palette_requested)
        self.theme_btn = self._icon_button("moon", "Switch to the light theme")
        self.theme_btn.clicked.connect(self.theme_toggled)

        bar.addWidget(self.scope_lbl)
        bar.addStretch()
        bar.addWidget(self.search)
        bar.addWidget(self.palette_btn)
        bar.addWidget(self.theme_btn)
        return header

    def _icon_button(self, glyph: str, tooltip: str) -> QPushButton:
        button = QPushButton()
        button.setObjectName("iconButton")
        button.setFixedSize(26, 24)
        button.setToolTip(tooltip)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setProperty("glyph", glyph)
        self._icon_buttons.append(button)
        return button

    def set_dark(self, is_dark: bool):
        """Point the theme button at the theme it switches *to*."""
        self._is_dark = is_dark
        self.theme_btn.setProperty("glyph", "moon" if is_dark else "sun")
        self.theme_btn.setToolTip(
            "Switch to the light theme" if is_dark else "Switch to the dark theme"
        )
        self._paint_icon_buttons()

    def _paint_icon_buttons(self):
        from ui.theme import palette

        colour = palette(dark=self._is_dark)["text_dim"]
        ratio = self.devicePixelRatioF() or 1.0
        for button in self._icon_buttons:
            button.setIcon(icons.icon(
                button.property("glyph") or "target", size=15,
                color=colour, ratio=ratio,
            ))
            button.setIconSize(QSize(15, 15))

    # ── Population ────────────────────────────────────────────────────────────

    def set_os(self, os_name: str, os_label: str = ""):
        """Rebuild the tiles for `os_name`. A no-op if it is already showing."""
        if os_name == self._os:
            return
        self._os = os_name
        self._clear()

        from ui.plugin_button import PluginButton   # local: avoids a cycle

        groups = self.registry.ribbon(os_name)
        for index, (category, color, plugins) in enumerate(groups):
            group = QWidget()
            group.setObjectName("ribbonGroup")
            column = QVBoxLayout(group)
            column.setContentsMargins(6, 0, 6, 0)
            column.setSpacing(3)

            heading = QLabel(category.upper())
            heading.setObjectName("ribbonHeading")
            heading.setFixedHeight(13)
            # The category colour is data rather than palette, so it is the one
            # thing here that has to be set per-widget.
            heading.setStyleSheet(f"color: {color}; background: transparent;")

            tiles = QWidget()
            tiles.setObjectName("ribbonTiles")
            tile_row = QHBoxLayout(tiles)
            tile_row.setContentsMargins(0, 0, 0, 0)
            tile_row.setSpacing(5)
            tile_row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

            ids: list[str] = []
            for info in plugins:
                button = PluginButton(info, compact=self._compact)
                button.clicked.connect(self.plugin_clicked)
                self._buttons[info.id] = button
                tile_row.addWidget(button)
                ids.append(info.id)

            column.addWidget(heading)
            column.addWidget(tiles, 1)
            self.row.insertWidget(self.row.count() - 1, group)
            self._groups.append((category, group, ids))

            if index < len(groups) - 1:
                divider = QFrame()
                divider.setObjectName("ribbonDivider")
                divider.setFrameShape(QFrame.Shape.VLine)
                divider.setFixedWidth(1)
                self.row.insertWidget(self.row.count() - 1, divider)
                self._dividers.append(divider)

        self.set_scope_label(os_label or os_name.title(), len(self._buttons))
        self._apply_filter(self.search.text())

    def reload(self, registry: PluginRegistry | None = None):
        """Rebuild from a (possibly re-inspected) registry, keeping the OS."""
        if registry is not None:
            self.registry = registry
        os_name, self._os = self._os, ""
        self.set_os(os_name or "", "")

    def set_scope_label(self, os_label: str, count: int | None = None):
        total = len(self._buttons) if count is None else count
        self.scope_lbl.setText(f"{total} {os_label.upper()} PLUGINS")

    def _clear(self):
        for _category, group, _ids in self._groups:
            group.setParent(None)
            group.deleteLater()
        for divider in self._dividers:
            divider.setParent(None)
            divider.deleteLater()
        self._groups.clear()
        self._dividers.clear()
        self._buttons.clear()

    # ── Filtering ─────────────────────────────────────────────────────────────

    def focus_search(self):
        self.search.setFocus()
        self.search.selectAll()

    def _apply_filter(self, text: str):
        needle = text.strip().lower()
        visible_total = 0

        for _category, group, ids in self._groups:
            shown = 0
            for plugin_id in ids:
                button = self._buttons.get(plugin_id)
                if button is None:
                    continue
                match = not needle or self._matches(button.info, needle)
                button.setVisible(match)
                shown += bool(match)
            group.setVisible(shown > 0)
            visible_total += shown

        # Dividers between two hidden groups would leave stray vertical rules.
        for divider in self._dividers:
            divider.setVisible(not needle)

        self.empty_lbl.setVisible(visible_total == 0 and bool(self._buttons))

    @staticmethod
    def _matches(info: PluginInfo, needle: str) -> bool:
        haystack = (
            f"{info.short_name} {info.id} {info.category} {info.description}"
        ).lower()
        return all(token in haystack for token in needle.split())

    # ── Density and state ─────────────────────────────────────────────────────

    def repaint_glyphs(self):
        """Re-render every tile's glyph, after a palette change."""
        for button in self._buttons.values():
            button._paint_glyph()
        self._paint_icon_buttons()

    def set_compact(self, compact: bool):
        if compact == self._compact:
            return
        self._compact = compact
        for button in self._buttons.values():
            button.set_compact(compact)
        self._apply_height()

    def _apply_height(self):
        self.setFixedHeight(_COMPACT_HEIGHT if self._compact else _COMFORTABLE_HEIGHT)

    @property
    def compact(self) -> bool:
        return self._compact

    def set_running(self, plugin_id: str, running: bool):
        button = self._buttons.get(plugin_id)
        if button is not None:
            button.set_running(running)

    def plugin_count(self) -> int:
        return len(self._buttons)
