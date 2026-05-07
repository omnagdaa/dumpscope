from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont


class PluginButton(QWidget):
    clicked = pyqtSignal(str, str)   # plugin_id, display_name

    def __init__(self, plugin_id: str, display_name: str, icon: str,
                 category_color: str = "#58a6ff", parent=None):
        super().__init__(parent)
        self.plugin_id = plugin_id
        self.display_name = display_name
        self.icon = icon
        self.category_color = category_color
        self._running = False
        self._build()
        self.setFixedSize(110, 100)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(6)
        layout.setContentsMargins(6, 10, 6, 10)

        self.icon_lbl = QLabel(self.icon)
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet("font-size: 28px; background: transparent;")

        self.name_lbl = QLabel(self.display_name)
        self.name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.name_lbl.setWordWrap(True)
        self.name_lbl.setStyleSheet(
            "font-size: 10px; font-weight: 600; background: transparent; color: #c9d1d9;"
        )

        self.spinner_lbl = QLabel("")
        self.spinner_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spinner_lbl.setStyleSheet("font-size: 9px; background: transparent; color: #58a6ff;")
        self.spinner_lbl.setVisible(False)

        layout.addWidget(self.icon_lbl)
        layout.addWidget(self.name_lbl)
        layout.addWidget(self.spinner_lbl)

        self._set_idle_style()
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def _set_idle_style(self):
        self.setStyleSheet(f"""
            PluginButton {{
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 10px;
            }}
            PluginButton:hover {{
                background-color: #1c2128;
                border: 1px solid {self.category_color};
            }}
        """)

    def _set_running_style(self):
        self.setStyleSheet(f"""
            PluginButton {{
                background-color: #0d1f33;
                border: 2px solid {self.category_color};
                border-radius: 10px;
            }}
        """)

    def set_running(self, running: bool):
        self._running = running
        if running:
            self._set_running_style()
            self.spinner_lbl.setText("● running")
            self.spinner_lbl.setVisible(True)
        else:
            self._set_idle_style()
            self.spinner_lbl.setVisible(False)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and not self._running:
            self.clicked.emit(self.plugin_id, self.display_name)
