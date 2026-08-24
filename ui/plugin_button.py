"""
A single tile on the plugin ribbon.

Colour handling here is still inline rather than stylesheet-driven; that gets
folded into the theme system along with the rest of the hardcoded palette.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from core.plugins import PluginInfo


class PluginButton(QWidget):
    """Emits the plugin id when clicked, unless a run is already in flight."""

    clicked = pyqtSignal(str)

    def __init__(self, info: PluginInfo, dark: bool = True, parent=None):
        super().__init__(parent)
        self.info = info
        self._dark = dark
        self._running = False
        self._build()
        self.setFixedSize(112, 104)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(5)
        layout.setContentsMargins(6, 10, 6, 8)

        self.icon_lbl = QLabel(self.info.icon or "🔬")
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet("font-size: 26px; background: transparent;")

        # Wrap the display name onto two lines so tiles stay a uniform height.
        self.name_lbl = QLabel(self._wrapped_name())
        self.name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.name_lbl.setWordWrap(True)
        self.name_lbl.setObjectName("pluginButtonLabel")

        self.badge_lbl = QLabel("")
        self.badge_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge_lbl.setObjectName("pluginButtonBadge")
        self.badge_lbl.setFixedHeight(12)
        if self.info.needs_input:
            self.badge_lbl.setText("needs input")

        layout.addWidget(self.icon_lbl)
        layout.addWidget(self.name_lbl)
        layout.addWidget(self.badge_lbl)

        tooltip = self.info.id
        if self.info.description:
            tooltip += f"\n\n{self.info.description}"
        if self.info.needs_input:
            required = ", ".join(a.name for a in self.info.required_args)
            tooltip += f"\n\nRequires: {required}"
        self.setToolTip(tooltip)

        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_style()

    def _wrapped_name(self) -> str:
        name = self.info.short_name
        if len(name) <= 12 or " " not in name:
            return name
        head, _, tail = name.partition(" ")
        return f"{head}\n{tail}"

    def set_dark(self, dark: bool):
        self._dark = dark
        self._apply_style()

    def set_running(self, running: bool):
        self._running = running
        self.badge_lbl.setText(
            "running…" if running else ("needs input" if self.info.needs_input else "")
        )
        self._apply_style()

    def _apply_style(self):
        color = self.info.color or "#8b949e"
        if self._running:
            background = "#0d1f33" if self._dark else "#e7f0fb"
            border = f"2px solid {color}"
        else:
            background = "#161b22" if self._dark else "#ffffff"
            border = "1px solid " + ("#30363d" if self._dark else "#d5d9de")
        hover_bg = "#1c2128" if self._dark else "#f2f6fa"
        self.setStyleSheet(f"""
            PluginButton {{
                background-color: {background};
                border: {border};
                border-radius: 10px;
            }}
            PluginButton:hover {{
                background-color: {hover_bg};
                border: 1px solid {color};
            }}
            QLabel#pluginButtonLabel {{
                font-size: 10px; font-weight: 600; background: transparent;
                color: {"#c9d1d9" if self._dark else "#3b4149"};
            }}
            QLabel#pluginButtonBadge {{
                font-size: 8px; font-weight: 700; background: transparent;
                color: {color}; letter-spacing: 0.5px;
            }}
        """)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and not self._running:
            self.clicked.emit(self.info.id)
