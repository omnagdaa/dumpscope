DARK_THEME = """
QMainWindow, QDialog {
    background-color: #232629;
    color: #e6edf3;
}

QWidget {
    background-color: #232629;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Ubuntu', sans-serif;
    font-size: 13px;
}

/* Labels */
QLabel {
    color: #e6edf3;
    background-color: transparent;
}

/* Case name highlight */
QLabel#caseNameLabel {
    color: #3daee9;
    font-weight: 600;
}

/* Inputs */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    padding: 8px 12px;
    color: #e6edf3;
    selection-background-color: #3daee9;
}

QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #3daee9;
}

QLineEdit:read-only {
    background-color: #232629;
    color: #8b949e;
    border: 1px solid #2f3338;
}

/* Output panel */
QPlainTextEdit#outputWindow, QTextEdit#outputWindow {
    background-color: #1e2228;
    color: #dcdfe4;
    border: 1px solid #3a3f45;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 12.5px;
}

/* Buttons */
QPushButton {
    background-color: #31363b;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    padding: 8px 20px;
    color: #e6edf3;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #3a3f45;
    border-color: #6e7681;
}

QPushButton:pressed {
    background-color: #2b2f33;
}

/* Primary */
QPushButton#primaryBtn {
    background-color: #3daee9;
    border-color: #3daee9;
    color: #ffffff;
}

QPushButton#primaryBtn:hover {
    background-color: #5ec4ff;
}

/* Danger */
QPushButton#dangerBtn {
    background-color: #e5534b;
    border-color: #ff6b63;
    color: #ffffff;
}

QPushButton#dangerBtn:hover {
    background-color: #ff6b63;
}

/* GroupBox */
QGroupBox {
    border: 1px solid #3a3f45;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: #9da5b4;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #2b2f33;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #4a5057;
    border-radius: 5px;
    min-height: 40px;
}

QScrollBar::handle:vertical:hover {
    background: #6a737d;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

/* Progress */
QProgressBar {
    border: 1px solid #3a3f45;
    border-radius: 4px;
    background-color: #2b2f33;
    text-align: center;
    color: #e6edf3;
}

QProgressBar::chunk {
    background-color: #3daee9;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #3a3f45;
    border-radius: 6px;
    background-color: #2b2f33;
}

QTabBar::tab {
    background-color: #232629;
    border: 1px solid #3a3f45;
    padding: 8px 16px;
    margin-right: 2px;
    border-radius: 6px 6px 0 0;
    color: #9da5b4;
}

QTabBar::tab:selected {
    background-color: #2b2f33;
    color: #e6edf3;
}

/* Lists */
QTreeWidget, QListWidget, QTableWidget {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    alternate-background-color: #31363b;
}

QTreeWidget::item:selected,
QListWidget::item:selected,
QTableWidget::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}

/* Header */
QHeaderView::section {
    background-color: #31363b;
    border-right: 1px solid #3a3f45;
    border-bottom: 1px solid #3a3f45;
    padding: 6px 10px;
    color: #9da5b4;
}

/* Menu */
QMenuBar {
    background-color: #2b2f33;
    border-bottom: 1px solid #3a3f45;
}

QMenuBar::item:selected {
    background-color: #31363b;
}

QMenu {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
}

QMenu::item:selected {
    background-color: #31363b;
}

/* Status */
QStatusBar {
    background-color: #2b2f33;
    border-top: 1px solid #3a3f45;
    color: #9da5b4;
}
"""


LIGHT_THEME = """
QMainWindow, QDialog {
    background-color: #eff0f1;
    color: #232629;
}

QWidget {
    background-color: #eff0f1;
    color: #232629;
    font-family: 'Segoe UI', 'Ubuntu', sans-serif;
    font-size: 13px;
}

/* Labels */
QLabel {
    color: #232629;
    background-color: transparent;
}

/* Case name highlight */
QLabel#caseNameLabel {
    color: #1f6feb;
    font-weight: 600;
}

/* Inputs */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    padding: 8px 12px;
    color: #232629;
    selection-background-color: #3daee9;
}

QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #3daee9;
}

QLineEdit:read-only {
    background-color: #eff0f1;
    color: #6e7681;
}

/* Output panel */
QPlainTextEdit#outputWindow, QTextEdit#outputWindow {
    background-color: #ffffff;
    color: #1e2228;
    border: 1px solid #c9ced6;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 12.5px;
    selection-background-color: #3daee9;
}

/* Buttons */
QPushButton {
    background-color: #e3e5e7;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    padding: 8px 20px;
    color: #232629;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #d5d9dd;
    border-color: #aeb6bf;
}

QPushButton:pressed {
    background-color: #c9ced6;
}

/* Primary */
QPushButton#primaryBtn {
    background-color: #3daee9;
    border-color: #3daee9;
    color: #ffffff;
}

QPushButton#primaryBtn:hover {
    background-color: #2f9fd8;
}

/* Danger */
QPushButton#dangerBtn {
    background-color: #e5534b;
    border-color: #e5534b;
    color: #ffffff;
}

QPushButton#dangerBtn:hover {
    background-color: #c9423a;
}

/* GroupBox */
QGroupBox {
    border: 1px solid #c9ced6;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: #5c6370;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #e3e5e7;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #aeb6bf;
    border-radius: 5px;
    min-height: 40px;
}

QScrollBar::handle:vertical:hover {
    background: #8c959f;
}

/* Lists */
QTreeWidget, QListWidget, QTableWidget {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    alternate-background-color: #f5f6f7;
}

/* Menu */
QMenuBar {
    background-color: #e3e5e7;
    border-bottom: 1px solid #c9ced6;
}

QMenu {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
}

/* Status */
QStatusBar {
    background-color: #e3e5e7;
    border-top: 1px solid #c9ced6;
    color: #5c6370;
}
"""
