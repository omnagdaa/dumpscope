"""
A single tile on the plugin ribbon.

Appearance is now entirely stylesheet-driven. The tile carries two dynamic
properties the theme reads back — ``state`` (idle / running / disabled) and
``density`` — instead of rebuilding an inline stylesheet on every state change.
That matters beyond tidiness: an inline stylesheet takes precedence over the
application stylesheet, so the old tiles could not be re-themed at all, and
toggling the theme left forty-nine hardcoded dark tiles on a light window.

The one colour still applied per-widget is the plugin's category colour, which
comes from data rather than from the palette and so cannot live in the theme.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import QLabel, QStyle, QStyleOption, QVBoxLayout, QWidget

from core.plugins import PluginInfo
from ui.theme import restyle

# (width, height, icon point size, wrap labels)
_SIZES = {
    "compact":     (88, 66, 16, True),
    "comfortable": (116, 100, 26, True),
}


class PluginButton(QWidget):
    """Emits the plugin id when clicked, unless a run is already in flight."""

    clicked = pyqtSignal(str)

    def __init__(self, info: PluginInfo, compact: bool = True, parent=None):
        super().__init__(parent)
        self.info = info
        self._density = "compact" if compact else "comfortable"
        self._running = False
        self._build()
        self._apply_density()

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(2)
        layout.setContentsMargins(4, 5, 4, 4)

        self.icon_lbl = QLabel(self.info.icon or "🔬")
        self.icon_lbl.setObjectName("pluginButtonIcon")
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.name_lbl = QLabel(self.info.short_name)
        self.name_lbl.setObjectName("pluginButtonLabel")
        self.name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.badge_lbl = QLabel("")
        self.badge_lbl.setObjectName("pluginButtonBadge")
        self.badge_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge_lbl.setFixedHeight(11)

        layout.addWidget(self.icon_lbl)
        layout.addWidget(self.name_lbl)
        layout.addWidget(self.badge_lbl)

        self.setToolTip(self._tooltip())
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("state", "idle")
        self._update_badge()

    def _tooltip(self) -> str:
        parts = [f"<b>{self.info.short_name}</b>", f"<code>{self.info.id}</code>"]
        if self.info.description:
            parts.append(self.info.description)
        if self.info.needs_input:
            required = ", ".join(a.name for a in self.info.required_args)
            parts.append(f"<i>Requires: {required}</i>")
        return "<br><br>".join(parts)

    # ── Density ───────────────────────────────────────────────────────────────

    def set_compact(self, compact: bool):
        density = "compact" if compact else "comfortable"
        if density == self._density:
            return
        self._density = density
        self._apply_density()

    def _apply_density(self):
        width, height, icon_size, wrap = _SIZES[self._density]
        self.setFixedSize(width, height)
        self.icon_lbl.setStyleSheet(f"font-size: {icon_size}px; background: transparent;")
        self.name_lbl.setWordWrap(wrap)
        self.name_lbl.setText(self._wrapped_name())
        self.badge_lbl.setVisible(self._density == "comfortable" or self._running)
        self.setProperty("density", self._density)
        restyle(self)

    def _wrapped_name(self) -> str:
        """
        Break at the first space so tiles stay a uniform height. Elision was
        tried instead and read badly — half the Windows ribbon came out as
        "Process Li…" / "Process Sc…" / "Command Li…", which is exactly the
        part of the name that distinguishes them.
        """
        name = self.info.short_name
        if len(name) <= 11 or " " not in name:
            return name
        head, _, tail = name.partition(" ")
        return f"{head}\n{tail}"

    # ── State ─────────────────────────────────────────────────────────────────

    def set_running(self, running: bool):
        self._running = running
        self.setProperty("state", "running" if running else "idle")
        self._update_badge()
        self.badge_lbl.setVisible(self._density == "comfortable" or running)
        restyle(self)

    def _update_badge(self):
        if self._running:
            self.badge_lbl.setText("running…")
        elif self.info.needs_input:
            self.badge_lbl.setText("needs input")
        else:
            self.badge_lbl.setText("")

    def paintEvent(self, event):
        """
        A bare QWidget subclass does not paint its own stylesheet background —
        Qt only does that for the widget classes it knows. Without this the
        tiles' background, border and rounded corners are all silently dropped
        and the ribbon renders as flat text on the window colour.
        """
        option = QStyleOption()
        option.initFrom(self)
        painter = QPainter(self)
        self.style().drawPrimitive(
            QStyle.PrimitiveElement.PE_Widget, option, painter, self
        )
        self._paint_accent(painter)

    def _paint_accent(self, painter: QPainter):
        """
        The category colour is data, not palette, so it cannot live in the
        theme. It is drawn as a bar along the top of the tile rather than
        pushed into the label's stylesheet, which would override the themed
        font along with the colour.
        """
        if not self.info.color:
            return
        painter.fillRect(7, 0, self.width() - 14, 2, QColor(self.info.color))

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and not self._running:
            self.clicked.emit(self.info.id)
