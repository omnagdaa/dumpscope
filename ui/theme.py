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
QLabel {
    color: #e6edf3;
    background-color: transparent;
}
QLabel#caseNameLabel {
    color: #3daee9;
    font-weight: 600;
}
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    padding: 8px 12px;
    color: #e6edf3;
    selection-background-color: #3daee9;
    selection-color: #ffffff;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #3daee9;
}
QLineEdit:read-only {
    background-color: #232629;
    color: #8b949e;
    border: 1px solid #2f3338;
}
QPlainTextEdit {
    background-color: #1e2228;
    color: #dcdfe4;
    border: 1px solid #3a3f45;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
}
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
    color: #e6edf3;
}
QPushButton:pressed {
    background-color: #2b2f33;
}
QPushButton:disabled {
    background-color: #2b2f33;
    color: #484f58;
    border-color: #2f3338;
}
QPushButton#primaryBtn {
    background-color: #3daee9;
    border-color: #3daee9;
    color: #ffffff;
}
QPushButton#primaryBtn:hover {
    background-color: #5ec4ff;
    color: #ffffff;
}
QPushButton#primaryBtn:disabled {
    background-color: #2b2f33;
    border-color: #3a3f45;
    color: #484f58;
}
QPushButton#dangerBtn {
    background-color: #e5534b;
    border-color: #ff6b63;
    color: #ffffff;
}
QPushButton#dangerBtn:hover {
    background-color: #ff6b63;
    color: #ffffff;
}
QGroupBox {
    border: 1px solid #3a3f45;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: #9da5b4;
    background-color: #232629;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #9da5b4;
    background-color: #232629;
}
QScrollArea {
    border: none;
    background-color: transparent;
}
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
QScrollBar:horizontal {
    background: #2b2f33;
    height: 10px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background: #4a5057;
    border-radius: 5px;
    min-width: 40px;
}
QScrollBar::handle:horizontal:hover {
    background: #6a737d;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
QProgressBar {
    border: 1px solid #3a3f45;
    border-radius: 4px;
    background-color: #2b2f33;
    text-align: center;
    color: #e6edf3;
}
QProgressBar::chunk {
    background-color: #3daee9;
    border-radius: 3px;
}
QTabWidget::pane {
    border: 1px solid #3a3f45;
    background-color: #232629;
}
QTabWidget::tab-bar {
    alignment: left;
}
QTabBar {
    background-color: #232629;
}
QTabBar::tab {
    background-color: #232629;
    border: 1px solid #3a3f45;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-radius: 6px 6px 0 0;
    color: #9da5b4;
}
QTabBar::tab:selected {
    background-color: #2b2f33;
    color: #e6edf3;
    border-bottom: 1px solid #2b2f33;
}
QTabBar::tab:hover:!selected {
    color: #e6edf3;
    background-color: #31363b;
}
QTabBar::scroller {
    background-color: #232629;
}
QTreeWidget, QListWidget {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    alternate-background-color: #31363b;
    color: #e6edf3;
    outline: none;
}
QTreeWidget::item, QListWidget::item {
    color: #e6edf3;
    padding: 4px 6px;
}
QTreeWidget::item:selected, QListWidget::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}
QTreeWidget::item:hover, QListWidget::item:hover {
    background-color: #31363b;
}
QTableWidget {
    background-color: #2b2f33;
    alternate-background-color: #31363b;
    color: #e6edf3;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    gridline-color: #3a3f45;
    selection-background-color: #3daee9;
    selection-color: #ffffff;
    outline: none;
}
QTableWidget::item {
    color: #e6edf3;
    padding: 2px 8px;
    border-bottom: 1px solid #3a3f45;
}
QTableWidget::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}
QTableWidget::item:hover {
    background-color: #3a3f45;
}
QHeaderView {
    background-color: #31363b;
}
QHeaderView::section {
    background-color: #31363b;
    border: none;
    border-right: 1px solid #3a3f45;
    border-bottom: 1px solid #3a3f45;
    padding: 6px 10px;
    color: #9da5b4;
    font-weight: 700;
    font-size: 11px;
}
QHeaderView::section:hover {
    background-color: #3a3f45;
    color: #e6edf3;
}
QComboBox {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    border-radius: 6px;
    padding: 6px 10px;
    color: #e6edf3;
}
QComboBox:hover {
    border-color: #6e7681;
}
QComboBox::drop-down {
    border: none;
    background: transparent;
}
QComboBox QAbstractItemView {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    color: #e6edf3;
    selection-background-color: #3daee9;
    selection-color: #ffffff;
}
QSplitter::handle {
    background-color: #3a3f45;
}
QMenuBar {
    background-color: #2b2f33;
    border-bottom: 1px solid #3a3f45;
    color: #e6edf3;
}
QMenuBar::item {
    background-color: transparent;
    color: #e6edf3;
    padding: 4px 10px;
}
QMenuBar::item:selected {
    background-color: #31363b;
    color: #e6edf3;
}
QMenu {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    color: #e6edf3;
}
QMenu::item {
    color: #e6edf3;
    padding: 6px 24px;
}
QMenu::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}
QMenu::separator {
    height: 1px;
    background-color: #3a3f45;
    margin: 4px 0;
}
QStatusBar {
    background-color: #2b2f33;
    border-top: 1px solid #3a3f45;
    color: #9da5b4;
}
QToolTip {
    background-color: #2b2f33;
    border: 1px solid #3a3f45;
    color: #e6edf3;
    padding: 4px 8px;
    border-radius: 4px;
}
QDialog {
    background-color: #232629;
}
QCheckBox {
    color: #e6edf3;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #3a3f45;
    border-radius: 3px;
    background-color: #2b2f33;
}
QCheckBox::indicator:checked {
    background-color: #3daee9;
    border-color: #3daee9;
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
QLabel {
    color: #232629;
    background-color: transparent;
}
QLabel#caseNameLabel {
    color: #1f6feb;
    font-weight: 600;
}
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    padding: 8px 12px;
    color: #232629;
    selection-background-color: #3daee9;
    selection-color: #ffffff;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #3daee9;
}
QLineEdit:read-only {
    background-color: #eff0f1;
    color: #6e7681;
    border: 1px solid #c9ced6;
}
QPlainTextEdit {
    background-color: #ffffff;
    color: #232629;
    border: 1px solid #c9ced6;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
}
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
    color: #232629;
}
QPushButton:pressed {
    background-color: #c9ced6;
}
QPushButton:disabled {
    background-color: #eff0f1;
    color: #aeb6bf;
    border-color: #c9ced6;
}
QPushButton#primaryBtn {
    background-color: #3daee9;
    border-color: #3daee9;
    color: #ffffff;
}
QPushButton#primaryBtn:hover {
    background-color: #2f9fd8;
    color: #ffffff;
}
QPushButton#primaryBtn:disabled {
    background-color: #c9ced6;
    border-color: #c9ced6;
    color: #6e7681;
}
QPushButton#dangerBtn {
    background-color: #e5534b;
    border-color: #e5534b;
    color: #ffffff;
}
QPushButton#dangerBtn:hover {
    background-color: #c9423a;
    color: #ffffff;
}
QGroupBox {
    border: 1px solid #c9ced6;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: #5c6370;
    background-color: #eff0f1;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #5c6370;
    background-color: #eff0f1;
}
QScrollArea {
    border: none;
    background-color: transparent;
}
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
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar:horizontal {
    background: #e3e5e7;
    height: 10px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background: #aeb6bf;
    border-radius: 5px;
    min-width: 40px;
}
QScrollBar::handle:horizontal:hover {
    background: #8c959f;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
QProgressBar {
    border: 1px solid #c9ced6;
    border-radius: 4px;
    background-color: #e3e5e7;
    text-align: center;
    color: #232629;
}
QProgressBar::chunk {
    background-color: #3daee9;
    border-radius: 3px;
}
QTabWidget::pane {
    border: 1px solid #c9ced6;
    background-color: #eff0f1;
}
QTabWidget::tab-bar {
    alignment: left;
}
QTabBar {
    background-color: #eff0f1;
}
QTabBar::tab {
    background-color: #eff0f1;
    border: 1px solid #c9ced6;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-radius: 6px 6px 0 0;
    color: #5c6370;
}
QTabBar::tab:selected {
    background-color: #ffffff;
    color: #232629;
    border-bottom: 1px solid #ffffff;
}
QTabBar::tab:hover:!selected {
    color: #232629;
    background-color: #d5d9dd;
}
QTabBar::scroller {
    background-color: #eff0f1;
}
QTreeWidget, QListWidget {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    alternate-background-color: #f5f6f7;
    color: #232629;
    outline: none;
}
QTreeWidget::item, QListWidget::item {
    color: #232629;
    padding: 4px 6px;
}
QTreeWidget::item:selected, QListWidget::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}
QTreeWidget::item:hover, QListWidget::item:hover {
    background-color: #e3e5e7;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f5f6f7;
    color: #232629;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    gridline-color: #e3e5e7;
    selection-background-color: #3daee9;
    selection-color: #ffffff;
    outline: none;
}
QTableWidget::item {
    color: #232629;
    padding: 2px 8px;
    border-bottom: 1px solid #e3e5e7;
}
QTableWidget::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}
QTableWidget::item:hover {
    background-color: #e3e5e7;
}
QHeaderView {
    background-color: #e3e5e7;
}
QHeaderView::section {
    background-color: #e3e5e7;
    border: none;
    border-right: 1px solid #c9ced6;
    border-bottom: 2px solid #c9ced6;
    padding: 6px 10px;
    color: #5c6370;
    font-weight: 700;
    font-size: 11px;
}
QHeaderView::section:hover {
    background-color: #d5d9dd;
    color: #232629;
}
QComboBox {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    border-radius: 6px;
    padding: 6px 10px;
    color: #232629;
}
QComboBox:hover {
    border-color: #aeb6bf;
}
QComboBox::drop-down {
    border: none;
    background: transparent;
}
QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    color: #232629;
    selection-background-color: #3daee9;
    selection-color: #ffffff;
}
QSplitter::handle {
    background-color: #c9ced6;
}
QMenuBar {
    background-color: #e3e5e7;
    border-bottom: 1px solid #c9ced6;
    color: #232629;
}
QMenuBar::item {
    background-color: transparent;
    color: #232629;
    padding: 4px 10px;
}
QMenuBar::item:selected {
    background-color: #d5d9dd;
    color: #232629;
}
QMenu {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    color: #232629;
}
QMenu::item {
    color: #232629;
    padding: 6px 24px;
}
QMenu::item:selected {
    background-color: #3daee9;
    color: #ffffff;
}
QMenu::separator {
    height: 1px;
    background-color: #c9ced6;
    margin: 4px 0;
}
QStatusBar {
    background-color: #e3e5e7;
    border-top: 1px solid #c9ced6;
    color: #5c6370;
}
QToolTip {
    background-color: #ffffff;
    border: 1px solid #c9ced6;
    color: #232629;
    padding: 4px 8px;
    border-radius: 4px;
}
QDialog {
    background-color: #eff0f1;
}
QCheckBox {
    color: #232629;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #c9ced6;
    border-radius: 3px;
    background-color: #ffffff;
}
QCheckBox::indicator:checked {
    background-color: #3daee9;
    border-color: #3daee9;
}
"""
