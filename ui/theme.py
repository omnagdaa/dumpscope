"""
The application stylesheet.

Previously this file was two 300-line blocks of literal QSS that had drifted
apart: a rule fixed in the dark block was often missing from the light one, and
widgets added later referenced object names neither block styled at all. Worst
of all both blocks styled ``QTableWidget`` while the results table — the surface
an examiner actually spends the day looking at — is a ``QTableView``, which
``QTableWidget`` selectors do not match. It was rendering unthemed.

So there is now one stylesheet template and two palettes. Every colour is a
token; the template contains no literal colours, which makes it impossible for
the two themes to diverge again.

Widgets should not set colours inline. Where a widget needs to look different
by state, give it a Qt property and style it here — see ``statusDot[state=…]``
and ``osBadge[os=…]``. Inline stylesheets win over the application stylesheet,
so an inline colour is a permanent theme override that no palette can reach.
"""

from __future__ import annotations

import re
from string import Template

# ── Palettes ──────────────────────────────────────────────────────────────────
# The accent ramp matches the plugin category colours in core.plugins, so the
# ribbon and the chrome around it belong to the same palette.

# Chrome is neutral graphite; hue is reserved for what carries meaning —
# severity, tags, event types, plugin categories — so any colour on screen
# says something about the evidence. The one accent is a steel blue for focus,
# selection and the primary action, the convention examiners already read in
# every other tool on their desk. Text pairs meet WCAG AA (4.5:1).
DARK = {
    "bg":            "#1d1e21",
    "surface":       "#232428",
    "surface_alt":   "#27292d",
    "surface_high":  "#2e3035",
    "border":        "#36393f",
    "border_strong": "#4b4f57",
    "text":          "#dfe1e5",
    "text_dim":      "#a2a8b0",
    "text_faint":    "#80868f",
    "accent":        "#5b9be0",
    "accent_hover":  "#78aee8",
    "accent_soft":   "#1f3047",
    # The accent is light enough to read as text on the dark ground, so text
    # printed on it has to be dark.
    "on_accent":     "#0b1626",
    "ok":            "#79b47f",
    "ok_soft":       "#1d2b20",
    "warn":          "#e0b05a",
    "warn_soft":     "#2f2817",
    "danger":        "#ec7a72",
    "danger_hover":  "#f2968f",
    "danger_soft":   "#33201f",
    "select":        "#2d4a6e",
    "on_select":     "#f2f5f8",
    "shadow":        "#0b0c0e",
}

LIGHT = {
    "bg":            "#f3f4f6",
    "surface":       "#ffffff",
    "surface_alt":   "#f6f7f9",
    "surface_high":  "#e9ebee",
    "border":        "#d6d9de",
    "border_strong": "#b3b8bf",
    "text":          "#1d2025",
    "text_dim":      "#4f5660",
    "text_faint":    "#666d77",
    "accent":        "#1f5fae",
    "accent_hover":  "#184c8c",
    "accent_soft":   "#e1ebf8",
    "on_accent":     "#ffffff",
    "ok":            "#2c7a36",
    "ok_soft":       "#e0f1e2",
    "warn":          "#8a5d00",
    "warn_soft":     "#faf0d8",
    "danger":        "#b8322b",
    "danger_hover":  "#932720",
    "danger_soft":   "#fbe4e2",
    # Soft selection with dark text, as in Explorer and Finder: a saturated
    # bar across a dense table is louder than the row it marks.
    "select":        "#d3e3f8",
    "on_select":     "#11161d",
    "shadow":        "#b3b8bf",
}


_FONTS = {
    # Each platform's own interface face first, so the app sits beside the
    # examiner's other tools rather than looking like a web page.
    "ui_font":   "'Segoe UI Variable Text', 'Segoe UI', 'IBM Plex Sans', '.AppleSystemUIFont', "
                 "'Noto Sans', 'Cantarell', sans-serif",
    "mono_font": "'Cascadia Mono', 'JetBrains Mono', 'IBM Plex Mono', 'Consolas', 'Menlo', "
                 "'DejaVu Sans Mono', monospace",
}

# The examiner's choices, if any. A chosen family is put in front of the stack
# rather than replacing it, so a name that is not actually installed degrades to
# the same fallbacks as before instead of to whatever Qt picks by default.
_OVERRIDES = {"ui_font": "", "mono_font": "", "scale": 1.0}

# Every size in the sheet is written against this base, so scaling all of them
# by (chosen size / BASE_FONT_SIZE) keeps the proportions the design has.
BASE_FONT_SIZE = 13
_SIZE_RE = re.compile(r"font-size:\s*(\d+)px")
MIN_FONT_SIZE = 7


# ── Template ──────────────────────────────────────────────────────────────────
# string.Template rather than str.format: QSS is full of literal braces.

_QSS = Template("""
/* ── Base ──────────────────────────────────────────────────────────────── */
QWidget {
    background-color: $bg;
    color: $text;
    font-family: $ui_font;
    font-size: 13px;
}
QMainWindow, QDialog { background-color: $bg; }
QLabel { background: transparent; color: $text; }
QToolTip {
    background-color: $surface_high;
    border: 1px solid $border;
    color: $text;
    padding: 5px 8px;
}

/* ── Text entry ────────────────────────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 6px 10px;
    color: $text;
    selection-background-color: $select;
    selection-color: $on_select;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus {
    border-color: $accent;
}
QLineEdit:read-only { background-color: $surface_alt; color: $text_dim; }
QLineEdit:disabled, QTextEdit:disabled { color: $text_faint; }
/* An unparseable regular expression in a filter box. */
QLineEdit[invalid="true"] {
    border-color: $danger;
    background-color: $danger_soft;
}
QPlainTextEdit#outputWindow {
    background-color: $bg;
    border: none;
    border-radius: 0;
    font-family: $mono_font;
    font-size: 12px;
    color: $text_dim;
}

/* ── Buttons ───────────────────────────────────────────────────────────── */
QPushButton {
    background-color: $surface_high;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 5px 14px;
    color: $text;
}
QPushButton:hover { background-color: $surface_alt; border-color: $border_strong; }
QPushButton:pressed { background-color: $surface; }
QPushButton:disabled {
    background-color: $surface;
    color: $text_faint;
    border-color: $border;
}
QPushButton#primaryBtn, QPushButton#primaryButton {
    font-weight: 600;
    background-color: $accent;
    border-color: $accent;
    color: $on_accent;
}
QPushButton#primaryBtn:hover, QPushButton#primaryButton:hover {
    background-color: $accent_hover;
    border-color: $accent_hover;
}
QPushButton#primaryBtn:disabled, QPushButton#primaryButton:disabled {
    background-color: $surface_high;
    border-color: $border;
    color: $text_faint;
}
QPushButton#dangerBtn, QPushButton#dangerButton {
    background-color: transparent;
    border-color: $danger;
    color: $danger;
}
QPushButton#dangerBtn:hover, QPushButton#dangerButton:hover {
    background-color: $danger;
    color: $on_accent;
}
QPushButton#dangerBtn:disabled, QPushButton#dangerButton:disabled {
    background-color: transparent;
    border-color: $border;
    color: $text_faint;
}
QPushButton:checked {
    background-color: $accent_soft;
    border-color: $accent;
    color: $accent;
}

/* ── Checkboxes ────────────────────────────────────────────────────────── */
QCheckBox { color: $text_dim; spacing: 6px; background: transparent; }
QCheckBox::indicator {
    width: 14px; height: 14px;
    border: 1px solid $border_strong;
    border-radius: 3px;
    background-color: $surface;
}
QCheckBox::indicator:checked { background-color: $accent; border-color: $accent; }
QRadioButton { color: $text_dim; spacing: 6px; background: transparent; }
QRadioButton:checked { color: $text; }
QRadioButton::indicator {
    width: 14px; height: 14px;
    border: 1px solid $border_strong;
    border-radius: 7px;
    background-color: $surface;
}
QRadioButton::indicator:checked {
    background-color: $accent;
    border: 3px solid $surface_high;
    width: 10px; height: 10px;
}

/* ── Group boxes ───────────────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid $border;
    border-radius: 4px;
    margin-top: 14px;
    padding: 14px 12px 12px 12px;
    font-weight: 600;
    font-size: 12px;
    color: $text;
    background-color: $surface;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    color: $text;
}

/* ── Scrollbars ────────────────────────────────────────────────────────── */
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 11px; margin: 0; }
QScrollBar:horizontal { background: transparent; height: 11px; margin: 0; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: $border_strong;
    border-radius: 5px;
}
QScrollBar::handle:vertical { min-height: 32px; }
QScrollBar::handle:horizontal { min-width: 32px; }
QScrollBar::handle:hover { background: $text_faint; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ── Progress ──────────────────────────────────────────────────────────── */
QProgressBar {
    border: none;
    border-radius: 3px;
    background-color: $surface_high;
    text-align: center;
    color: $text_dim;
    font-size: 11px;
}
QProgressBar::chunk { background-color: $accent; border-radius: 3px; }

/* ── Tabs ──────────────────────────────────────────────────────────────── */
QTabWidget::pane { border: none; border-top: 1px solid $border; background-color: $bg; }
QTabBar { background-color: $bg; qproperty-drawBase: 0; }
QTabBar::tab {
    background-color: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 7px 14px;
    margin: 0;
    color: $text_dim;
}
QTabBar::tab:selected { color: $text; border-bottom-color: $accent; }
QTabBar::tab:hover:!selected { color: $text; background-color: $surface_alt; }
/* Many tabs: cap each one so more fit, and make the overflow controls
   targets a pointer can actually hit. */
QTabBar::tab { max-width: 220px; }
QTabBar QToolButton {
    background-color: $surface;
    border: none;
    border-left: 1px solid $border;
    width: 22px;
}
QTabBar QToolButton:hover { background-color: $surface_high; }
QToolButton#tabListButton {
    background-color: transparent;
    border: none;
    border-left: 1px solid $border;
    padding: 4px 10px;
    color: $text_dim;
}
QToolButton#tabListButton:hover { background-color: $surface_high; color: $text; }
QToolButton#tabListButton::menu-indicator { image: none; width: 0; }
QPushButton#tabCloseButton {
    border: none;
    background: transparent;
    border-radius: 4px;
    padding: 0;
    margin: 0;
}
QPushButton#tabCloseButton:hover { background-color: $surface_high; }

/* ── Item views ────────────────────────────────────────────────────────── */
/* QTableView is listed explicitly: it is the results grid, and it is NOT a
   QTableWidget, so QTableWidget selectors never reached it. */
QTableView, QTableWidget, QTreeView, QTreeWidget, QListView, QListWidget {
    background-color: $surface;
    alternate-background-color: $surface_alt;
    color: $text;
    border: none;
    gridline-color: $border;
    selection-background-color: $select;
    selection-color: $on_select;
    outline: none;
}
QTableView::item, QTableWidget::item { padding: 2px 8px; border: none; }
QTreeView::item, QTreeWidget::item, QListView::item, QListWidget::item {
    padding: 4px 6px;
    border: none;
}
QTableView::item:selected, QTableWidget::item:selected,
QTreeView::item:selected, QTreeWidget::item:selected,
QListView::item:selected, QListWidget::item:selected {
    background-color: $select;
    color: $on_select;
}
QTreeView::item:hover, QTreeWidget::item:hover,
QListView::item:hover, QListWidget::item:hover {
    background-color: $surface_high;
}
QHeaderView { background-color: $surface_high; }
QHeaderView::section {
    background-color: $surface_high;
    border: none;
    border-right: 1px solid $border;
    border-bottom: 1px solid $border;
    padding: 5px 8px;
    color: $text_dim;
    font-weight: 600;
    font-size: 12px;
}
QHeaderView::section:hover { background-color: $surface_alt; color: $text; }
QTableView QTableCornerButton::section {
    background-color: $surface_high;
    border: none;
}

/* ── Combo boxes ───────────────────────────────────────────────────────── */
QComboBox {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 5px 10px;
    color: $text;
}
QComboBox:hover { border-color: $border_strong; }
QComboBox:focus { border-color: $accent; }
QComboBox::drop-down { border: none; width: 18px; }
QComboBox QAbstractItemView {
    background-color: $surface;
    border: 1px solid $border;
    color: $text;
    selection-background-color: $select;
    selection-color: $on_select;
}

/* ── Menus, status, splitters ──────────────────────────────────────────── */
QMenuBar { background-color: $surface; border-bottom: 1px solid $border; color: $text; }
QMenuBar::item { background: transparent; padding: 5px 10px; border-radius: 4px; }
QMenuBar::item:selected { background-color: $surface_high; }
QMenu {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 4px;
    color: $text;
}
QMenu::item { padding: 6px 22px; border-radius: 4px; }
QMenu::item:selected { background-color: $select; color: $on_select; }
QMenu::separator { height: 1px; background-color: $border; margin: 4px 6px; }
QStatusBar {
    background-color: $surface;
    border-top: 1px solid $border;
    color: $text_dim;
    font-size: 12px;
}
QStatusBar::item { border: none; }
QSplitter::handle { background-color: $border; }
QSplitter::handle:hover { background-color: $accent; }

/* ── Docks ─────────────────────────────────────────────────────────────── */
QDockWidget {
    color: $text_dim;
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}
QDockWidget::title {
    background-color: $surface_high;
    padding: 7px 12px;
    border-bottom: 1px solid $border;
    font-size: 11px;
    font-weight: 600;
}
QWidget#caseTree, QWidget#tagPanel { background-color: $surface; }
QTreeWidget#caseTree, QTreeWidget#tagTree { background-color: $surface; }

/* Section headers inside the dock. */
QWidget#dockHeader {
    background-color: $surface_high;
    border-top: 1px solid $border;
    border-bottom: 1px solid $border;
}
QLabel#dockHeading {
    font-size: 12px;
    font-weight: 600;
    color: $text_faint;
}
QPushButton#iconButton {
    background: transparent;
    border: none;
    border-radius: 4px;
    padding: 0;
    color: $text_dim;
    font-size: 15px;
    font-weight: 600;
}
QPushButton#iconButton:hover { background-color: $surface_alt; color: $accent; }

/* ── Case header (top of the left sidebar) ─────────────────────────────── */
/* The window used to open with a title bar carrying the product name and the
   case name. Neither is a working surface: the name of the tool is known to
   whoever launched it, and the case belongs beside the case explorer. */
QWidget#caseSidebar { background-color: $surface; }
QWidget#caseHeader {
    background-color: $surface_alt;
    border-bottom: 1px solid $border;
}
QLabel#caseTag, QLabel#caseNameLabel {
    font-size: 13px;
    font-weight: 600;
    color: $text;
}
QLabel#imageLabel { font-size: 12px; color: $text_dim; }
QLabel#imageLabel[loaded="false"] { color: $text_faint; font-style: italic; }

/* The OS badge is set by property, not inline stylesheet, so a theme change
   repaints it along with everything else. */
QLabel#osGlyph { background: transparent; padding-left: 4px; }
QLabel#osBadge {
    border-radius: 4px;
    padding: 3px 9px 3px 5px;
    font-size: 11px;
    font-weight: 600;
    background-color: $surface_high;
    color: $text_dim;
}
QLabel#osBadge[os="windows"] { background-color: $accent_soft; color: $accent; }
QLabel#osBadge[os="linux"]   { background-color: $ok_soft; color: $ok; }
QLabel#osBadge[os="mac"]     { background-color: $warn_soft; color: $warn; }
QLabel#osBadge[probing="true"] {
    background-color: $surface_high;
    color: $text_faint;
}

/* ── Toasts ────────────────────────────────────────────────────────────── */
/* A status bar holds one message, so six plugins finishing overwrite each
   other and none of them is visible from another window. */
QWidget#toast {
    background-color: $surface_high;
    border: 1px solid $border;
    border-left: 3px solid $accent;
    border-radius: 4px;
}
QWidget#toast[level="success"] { border-left-color: $ok; }
QWidget#toast[level="warning"] { border-left-color: $warn; }
QWidget#toast[level="error"]   { border-left-color: $danger; }
QLabel#toastTitle {
    font-size: 12px;
    font-weight: 600;
    color: $text;
    background: transparent;
}
QLabel#toastBody { font-size: 11px; color: $text_dim; background: transparent; }
QLabel#toastGlyph { background: transparent; }

/* ── Command palette ───────────────────────────────────────────────────── */
QDialog#commandPalette {
    background-color: $surface;
    border: 1px solid $border_strong;
    border-radius: 4px;
}
QLineEdit#paletteInput {
    background-color: transparent;
    border: none;
    border-bottom: 1px solid $border;
    border-radius: 0;
    padding: 0 14px;
    font-size: 14px;
    color: $text;
}
QListWidget#paletteList {
    background-color: transparent;
    border: none;
    padding: 4px 4px 6px 4px;
}
QListWidget#paletteList::item { padding: 4px 10px; border-radius: 4px; }
QLabel#paletteEmpty {
    color: $text_faint;
    padding: 26px;
    qproperty-alignment: AlignCenter;
}

/* ── Plugin ribbon ─────────────────────────────────────────────────────── */
QWidget#pluginRibbon {
    background-color: $bg;
    border-bottom: 1px solid $border;
}
QWidget#ribbonInner, QWidget#ribbonGroup, QWidget#ribbonTiles { background: transparent; }
QFrame#ribbonDivider { color: $border; background-color: $border; border: none; }
QLabel#ribbonHeading {
    font-size: 11px;
    font-weight: 600;
    color: $text_faint;
}
QLineEdit#pluginSearch {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 12px;
}
/* Overflow is reached by wheel or search; the bar is a hint, not a control. */
QScrollArea#ribbonScroll QScrollBar:horizontal { height: 4px; }
QScrollArea#ribbonScroll QScrollBar::handle:horizontal { border-radius: 2px; }
QLabel#ribbonEmpty { color: $text_faint; font-style: italic; font-size: 12px; }

/* Tiles. The plugin's category colour is applied as a border/text accent by
   PluginButton via a dynamic property, which the theme reads back here. */
PluginButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
}
PluginButton:hover { background-color: $surface_high; border-color: $border; }
PluginButton[state="running"] {
    background-color: $accent_soft;
    border-color: $accent;
}
PluginButton[state="disabled"] { background-color: transparent; }
QLabel#pluginButtonLabel { font-size: 11px; color: $text; }
QLabel#pluginButtonIcon { font-size: 22px; }
QLabel#pluginButtonBadge {
    font-size: 8px;
    font-weight: 600;
    color: $text_faint;
}
PluginButton[state="running"] QLabel#pluginButtonBadge { color: $accent; }

/* ── Result panel ──────────────────────────────────────────────────────── */
QWidget#resultToolbar {
    background-color: $surface;
    border-bottom: 1px solid $border;
}
QLabel#panelTitle { font-size: 13px; font-weight: 600; color: $text; }
QLabel#panelStage { font-size: 11px; color: $text_faint; }
QLabel#panelRowCount {
    font-size: 11px;
    font-weight: 600;
    color: $text_dim;
    font-family: $mono_font;
}
QLabel#statusDot { font-size: 13px; color: $text_faint; }
QLabel#statusDot[state="running"]   { color: $accent; }
QLabel#statusDot[state="done"]      { color: $ok; }
QLabel#statusDot[state="error"]     { color: $danger; }
QLabel#statusDot[state="cancelled"] { color: $warn; }

/* ── Overview tab ──────────────────────────────────────────────────────── */
QLabel#overviewTitle { font-size: 18px; font-weight: 600; color: $text; }
QLabel#overviewBlurb { font-size: 12px; color: $text_dim; }
QWidget#statCard {
    background-color: $surface_alt;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 4px;
}
QLabel#statValue {
    font-size: 17px;
    font-weight: 600;
    color: $text;
    font-family: $mono_font;
}
QLabel#statTitle {
    font-size: 11px;
    font-weight: 600;
    color: $text_faint;
}

/* ── Case launcher ─────────────────────────────────────────────────────── */
QWidget#launcherSidebar {
    background-color: $surface;
    border-right: 1px solid $border;
}
QLabel#launcherLogo { font-size: 20px; font-weight: 600; color: $text; }
QLabel#launcherTagline { font-size: 12px; color: $text_dim; }
QLabel#launcherHint { font-size: 11px; color: $text_faint; }
QLabel#launcherHeading {
    font-size: 13px;
    font-weight: 600;
    color: $text_faint;
}
QFrame#launcherDivider { background-color: $border; border: none; }
QFrame#launcherEmpty {
    border: 1px dashed $border;
    border-radius: 4px;
}
QLabel#launcherEmptyTitle { font-size: 16px; font-weight: 600; color: $text; }
QLabel#launcherEmptyText { font-size: 12px; color: $text_dim; }
QListWidget#recentList {
    background-color: transparent;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 4px;
}
QListWidget#recentList::item {
    padding: 8px 10px;
    border-radius: 4px;
    color: $text;
}
QListWidget#recentList::item:selected { background-color: $select; color: $on_select; }

/* ── Timeline and insights ─────────────────────────────────────────────── */
QPushButton#timelineChip {
    padding: 4px 10px;
    font-size: 11px;
    border-radius: 4px;
    background-color: $surface_alt;
    color: $text_faint;
}
QPushButton#timelineChip:checked { background-color: $surface_high; color: $text; }
QFrame#timeRangePopup {
    background-color: $surface;
    border: 1px solid $border_strong;
    border-radius: 4px;
}
QLabel#popupHeading { font-size: 13px; font-weight: 600; color: $text; }
QPushButton#quickRange {
    background: transparent;
    border: none;
    color: $accent;
    text-align: left;
    padding: 4px 6px;
}
QPushButton#quickRange:hover { background-color: $accent_soft; }
QDateTimeEdit {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 4px;
    padding: 4px 8px;
    color: $text;
}
QDateTimeEdit:focus { border-color: $accent; }
QCalendarWidget QWidget { alternate-background-color: $surface_alt; }
QCalendarWidget QToolButton { background: transparent; border: none; color: $text; padding: 4px 8px; }
QCalendarWidget QAbstractItemView:disabled { color: $text_faint; }
QFrame#insightCard {
    background-color: transparent;
    border: 1px solid $border;
    border-radius: 4px;
}
QFrame#insightCard:hover { background-color: $surface_high; }
QFrame#insightCard[selected="true"] { background-color: $accent_soft; border-color: $accent; }
QLabel#insightCount { font-size: 13px; font-weight: 600; color: $text; background: transparent; }
QLabel#insightLabel { font-size: 13px; color: $text_dim; background: transparent; }
QLabel#reportOption { font-size: 12px; color: $text_dim; }

/* ── Dialogs and wizard ────────────────────────────────────────────────── */
QLabel#dialogHeading { font-size: 16px; font-weight: 600; color: $text; }
QLabel#dialogBlurb { font-size: 12px; color: $text_dim; }
QWidget#wizardHeader {
    background-color: $surface;
    border-bottom: 1px solid $border;
}
QWidget#wizardFooter {
    background-color: $surface;
    border-top: 1px solid $border;
}
QWidget#stepContainer { background: transparent; }
QFrame#stepLine { background-color: $border; border: none; }
QLabel#stepLabel { font-size: 11px; color: $text_faint; }
QLabel#stepLabel[state="active"] { color: $accent; font-weight: 600; }
QLabel#stepLabel[state="done"] { color: $ok; }
QLabel#stepCircle {
    border-radius: 13px;
    font-weight: 600;
    font-size: 12px;
    background-color: $surface_high;
    color: $text_faint;
    border: 1px solid $border;
}
QLabel#stepCircle[state="active"] {
    background-color: $accent;
    color: $on_accent;
    border-color: $accent;
}
QLabel#stepCircle[state="done"] {
    background-color: $ok;
    color: $on_accent;
    border-color: $ok;
}
QLabel#wizardTitle { font-size: 18px; font-weight: 600; color: $text; }
QLabel#wizardSubtitle { font-size: 12px; color: $text_dim; }
QLabel#fieldLabel { font-size: 13px; color: $text_dim; }
QLabel#fieldValue { font-size: 13px; color: $text; }
QLabel#fieldHint { font-size: 11px; color: $text_dim; }
QLabel#requiredNote { font-size: 11px; color: $danger; }
QLabel#hintOk { color: $ok; font-size: 12px; }
QLabel#hintWarn { color: $warn; font-size: 12px; }
QLabel#hintError { color: $danger; font-size: 12px; }

/* The wizard's drop zone: one rule per state rather than three inline sheets. */
QWidget#dropZone {
    border: 2px dashed $border_strong;
    border-radius: 4px;
    background-color: $surface;
}
QWidget#dropZone[state="hover"] { border-color: $accent; background-color: $accent_soft; }
QWidget#dropZone[state="loaded"] { border-style: solid; border-color: $ok; background-color: $ok_soft; }
QLabel#dropIcon { font-size: 32px; }
QLabel#dropTitle { font-size: 14px; font-weight: 600; color: $text; }
QLabel#dropSubtitle { font-size: 11px; color: $text_dim; }
QLabel#dropFile { font-size: 12px; font-weight: 600; color: $ok; }
""")


def set_fonts(ui_font: str = "", mono_font: str = "", size: int = BASE_FONT_SIZE):
    """
    Choose the interface fonts. Empty names keep the built-in stacks.

    Applies to the next `build`; callers restyle the application themselves,
    since a font change is a full re-render either way.
    """
    _OVERRIDES["ui_font"] = (ui_font or "").strip()
    _OVERRIDES["mono_font"] = (mono_font or "").strip()
    _OVERRIDES["scale"] = max(0.6, min(2.5, (size or BASE_FONT_SIZE) / BASE_FONT_SIZE))


def fonts() -> dict:
    """The current choices: family names (possibly empty) and the base size."""
    return {
        "ui_font": _OVERRIDES["ui_font"],
        "mono_font": _OVERRIDES["mono_font"],
        "size": round(BASE_FONT_SIZE * _OVERRIDES["scale"]),
    }


def mono_family() -> str:
    """The monospace family to hand a QFont, for the places QSS cannot reach."""
    if _OVERRIDES["mono_font"]:
        return _OVERRIDES["mono_font"]
    from PyQt6.QtGui import QFontDatabase
    installed = set(QFontDatabase.families())
    stack = [f.strip().strip("'") for f in _FONTS["mono_font"].split(",")]
    return next((f for f in stack if f in installed), "monospace")


def _stack(key: str) -> str:
    chosen = _OVERRIDES[key]
    return f"'{chosen}', {_FONTS[key]}" if chosen else _FONTS[key]


def _scale_sizes(sheet: str) -> str:
    scale = _OVERRIDES["scale"]
    if scale == 1.0:
        return sheet
    return _SIZE_RE.sub(
        lambda m: f"font-size: {max(MIN_FONT_SIZE, round(int(m.group(1)) * scale))}px",
        sheet,
    )


def build(dark: bool = True) -> str:
    """Render the stylesheet for one of the two palettes."""
    tokens = dict(
        DARK if dark else LIGHT,
        ui_font=_stack("ui_font"), mono_font=_stack("mono_font"),
    )
    return _scale_sizes(_QSS.substitute(tokens))


def palette(dark: bool = True) -> dict:
    """The raw tokens, for the rare place that needs a colour in Python."""
    return dict(DARK if dark else LIGHT)


def _luminance(hex_color: str) -> float:
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def readable(color: str, dark: bool = True) -> str:
    """
    A data colour (severity, event type) adjusted to be legible as text.

    Those colours are tuned for the dark ground. On the light one they are
    darkened, keeping their hue, until they reach WCAG AA (4.5:1) against it.
    """
    if dark or not color.startswith("#") or len(color) != 7:
        return color
    from PyQt6.QtGui import QColor
    ground = _luminance(LIGHT["surface"])
    hue, sat, light, _ = QColor(color).getHsl()
    adjusted = color
    while light > 0 and (ground + 0.05) / (_luminance(adjusted) + 0.05) < 4.5:
        light = max(0, light - 6)
        adjusted = QColor.fromHsl(hue, sat, light).name()
    return adjusted


def restyle(widget) -> None:
    """
    Re-evaluate the stylesheet for `widget` after one of its Qt properties
    changed. Qt does not repolish automatically, so a property-driven rule
    (``statusDot[state=…]``) otherwise keeps the appearance it was born with.
    """
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


# Kept so existing imports keep working; both are now generated from one source.
DARK_THEME = build(dark=True)
LIGHT_THEME = build(dark=False)
