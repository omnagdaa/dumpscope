from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPlainTextEdit, QPushButton, QScrollArea,
    QSizePolicy, QFrame, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QTextCursor


class ResultPanel(QWidget):
    """Displays streamed output from a Volatility3 plugin."""

    def __init__(self, plugin_name: str, parent=None):
        super().__init__(parent)
        self.plugin_name = plugin_name
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setObjectName("resultToolbar")
        toolbar.setFixedHeight(42)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(14, 0, 14, 0)
        tb_layout.setSpacing(10)

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet("color: #f0883e; font-size: 10px; background: transparent;")

        self.title_lbl = QLabel(f"  {self.plugin_name}")
        self.title_lbl.setStyleSheet(
            "font-size: 13px; font-weight: 700; background: transparent; color: #e6edf3;"
        )

        self.line_count = QLabel("0 lines")
        self.line_count.setStyleSheet("color: #8b949e; font-size: 11px; background: transparent;")

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(65)
        copy_btn.clicked.connect(self._copy_all)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(65)
        clear_btn.clicked.connect(self._clear)

        tb_layout.addWidget(self.status_dot)
        tb_layout.addWidget(self.title_lbl)
        tb_layout.addStretch()
        tb_layout.addWidget(self.line_count)
        tb_layout.addWidget(copy_btn)
        tb_layout.addWidget(clear_btn)

        # Output area
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        mono = QFont("JetBrains Mono, Fira Code, Consolas, monospace", 11)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.output.setFont(mono)
        self.output.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0d1117;
                color: #e6edf3;
                border: none;
                border-top: 1px solid #30363d;
                padding: 10px;
                selection-background-color: #1f6feb;
            }
        """)

        layout.addWidget(toolbar)
        layout.addWidget(self.output, 1)

    def append_line(self, line: str):
        self.output.appendPlainText(line)
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output.setTextCursor(cursor)
        count = self.output.document().lineCount()
        self.line_count.setText(f"{count} lines")

    def set_running(self, running: bool):
        if running:
            self.status_dot.setStyleSheet("color: #f0883e; font-size: 10px; background: transparent;")
            self.status_dot.setText("◉")
        else:
            self.status_dot.setStyleSheet("color: #3fb950; font-size: 10px; background: transparent;")
            self.status_dot.setText("●")

    def set_error(self, msg: str):
        self.status_dot.setStyleSheet("color: #f85149; font-size: 10px; background: transparent;")
        self.status_dot.setText("✕")
        self.append_line(f"\n[ERROR] {msg}")

    def _copy_all(self):
        QApplication.clipboard().setText(self.output.toPlainText())

    def _clear(self):
        self.output.clear()
        self.line_count.setText("0 lines")
