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

from string import Template

# ── Palettes ──────────────────────────────────────────────────────────────────
# The accent ramp matches the plugin category colours in core.plugins, so the
# ribbon and the chrome around it belong to the same palette.

DARK = {
    "bg":            "#0d1117",
    "surface":       "#161b22",
    "surface_alt":   "#1c2128",
    "surface_high":  "#21262d",
    "border":        "#30363d",
    "border_strong": "#484f58",
    "text":          "#e6edf3",
    "text_dim":      "#8b949e",
    "text_faint":    "#6e7681",
    "accent":        "#58a6ff",
    "accent_hover":  "#79c0ff",
    "accent_soft":   "#132b47",
    "on_accent":     "#ffffff",
    "ok":            "#3fb950",
    "ok_soft":       "#0f2419",
    "warn":          "#e3b341",
    "warn_soft":     "#2b2211",
    "danger":        "#f85149",
    "danger_hover":  "#ff6b63",
    "danger_soft":   "#2d1416",
    "select":        "#1f6feb",
    "on_select":     "#ffffff",
    "shadow":        "#010409",
}

LIGHT = {
    "bg":            "#f6f8fa",
    "surface":       "#ffffff",
    "surface_alt":   "#f0f3f6",
    "surface_high":  "#eaeef2",
    "border":        "#d0d7de",
    "border_strong": "#afb8c1",
    "text":          "#1f2328",
    "text_dim":      "#59636e",
    "text_faint":    "#818b98",
    "accent":        "#0969da",
    "accent_hover":  "#218bff",
    "accent_soft":   "#ddf4ff",
    "on_accent":     "#ffffff",
    "ok":            "#1a7f37",
    "ok_soft":       "#dafbe1",
    "warn":          "#9a6700",
    "warn_soft":     "#fff8c5",
    "danger":        "#cf222e",
    "danger_hover":  "#a40e26",
    "danger_soft":   "#ffebe9",
    "select":        "#0969da",
    "on_select":     "#ffffff",
    "shadow":        "#8c959f",
}

_FONTS = {
    "ui_font":   "'Inter', 'Segoe UI', 'Ubuntu', 'Cantarell', sans-serif",
    "mono_font": "'JetBrains Mono', 'Cascadia Mono', 'Consolas', 'DejaVu Sans Mono', monospace",
}


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
    border-radius: 6px;
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
    border-radius: 6px;
    padding: 6px 14px;
    color: $text;
    font-weight: 600;
}
QPushButton:hover { background-color: $surface_alt; border-color: $border_strong; }
QPushButton:pressed { background-color: $surface; }
QPushButton:disabled {
    background-color: $surface;
    color: $text_faint;
    border-color: $border;
}
QPushButton#primaryBtn, QPushButton#primaryButton {
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

/* ── Group boxes ───────────────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid $border;
    border-radius: 8px;
    margin-top: 14px;
    padding: 14px 12px 12px 12px;
    font-weight: 700;
    font-size: 11px;
    color: $text_dim;
    background-color: $surface;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: $text_dim;
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
    padding: 7px 16px;
    margin: 0;
    color: $text_dim;
    font-weight: 600;
}
QTabBar::tab:selected { color: $text; border-bottom-color: $accent; }
QTabBar::tab:hover:!selected { color: $text; background-color: $surface_alt; }
QTabBar::close-button {
    image: none;
    background: transparent;
    border-radius: 6px;
    subcontrol-position: right;
}
QTabBar::close-button:hover { background: $danger; }

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
    font-weight: 700;
    font-size: 11px;
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
    border-radius: 6px;
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
    border-radius: 6px;
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
    font-weight: 700;
}
QWidget#caseTree { background-color: $surface; }
QTreeWidget#caseTree { border-right: 1px solid $border; }

/* ── Application chrome ────────────────────────────────────────────────── */
QWidget#topBar {
    background-color: $surface;
    border-bottom: 1px solid $border;
}
QLabel#appLogo {
    font-size: 15px;
    font-weight: 800;
    color: $accent;
    letter-spacing: 0.5px;
}
QLabel#caseTag, QLabel#caseNameLabel {
    font-size: 12px;
    font-weight: 700;
    color: $text;
}
QLabel#imageLabel { font-size: 12px; color: $text_dim; }
QLabel#imageLabel[loaded="false"] { color: $text_faint; font-style: italic; }

/* The OS badge is set by property, not inline stylesheet, so a theme change
   repaints it along with everything else. */
QLabel#osBadge {
    border-radius: 4px;
    padding: 3px 9px;
    font-size: 11px;
    font-weight: 700;
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

/* ── Plugin ribbon ─────────────────────────────────────────────────────── */
QWidget#pluginRibbon {
    background-color: $bg;
    border-bottom: 1px solid $border;
}
QWidget#ribbonInner, QWidget#ribbonGroup, QWidget#ribbonTiles { background: transparent; }
QFrame#ribbonDivider { color: $border; background-color: $border; border: none; }
QLabel#ribbonHeading {
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 1.4px;
    color: $text_faint;
}
QLineEdit#pluginSearch {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 13px;
    padding: 4px 12px;
    font-size: 12px;
}
QLabel#ribbonEmpty { color: $text_faint; font-style: italic; font-size: 12px; }

/* Tiles. The plugin's category colour is applied as a border/text accent by
   PluginButton via a dynamic property, which the theme reads back here. */
PluginButton {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: 8px;
}
PluginButton:hover { background-color: $surface_high; border-color: $border_strong; }
PluginButton[state="running"] {
    background-color: $accent_soft;
    border-color: $accent;
}
PluginButton[state="disabled"] { background-color: $bg; border-color: $border; }
QLabel#pluginButtonLabel { font-size: 10px; font-weight: 600; color: $text; }
QLabel#pluginButtonIcon { font-size: 22px; }
QLabel#pluginButtonBadge {
    font-size: 8px;
    font-weight: 800;
    letter-spacing: 0.4px;
    color: $text_faint;
}
PluginButton[state="running"] QLabel#pluginButtonBadge { color: $accent; }

/* ── Result panel ──────────────────────────────────────────────────────── */
QWidget#resultToolbar {
    background-color: $surface;
    border-bottom: 1px solid $border;
}
QLabel#panelTitle { font-size: 13px; font-weight: 700; color: $text; }
QLabel#panelStage { font-size: 11px; color: $text_faint; }
QLabel#panelRowCount {
    font-size: 11px;
    font-weight: 700;
    color: $text_dim;
    font-family: $mono_font;
}
QLabel#statusDot { font-size: 13px; color: $text_faint; }
QLabel#statusDot[state="running"]   { color: $accent; }
QLabel#statusDot[state="done"]      { color: $ok; }
QLabel#statusDot[state="error"]     { color: $danger; }
QLabel#statusDot[state="cancelled"] { color: $warn; }

/* ── Overview tab ──────────────────────────────────────────────────────── */
QLabel#overviewTitle { font-size: 20px; font-weight: 800; color: $text; }
QLabel#overviewBlurb { font-size: 12px; color: $text_dim; }
QWidget#statCard {
    background-color: $surface_alt;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 4px;
}
QLabel#statValue {
    font-size: 17px;
    font-weight: 700;
    color: $text;
    font-family: $mono_font;
}
QLabel#statTitle {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    color: $text_faint;
}

/* ── Case launcher ─────────────────────────────────────────────────────── */
QWidget#launcherSidebar {
    background-color: $surface;
    border-right: 1px solid $border;
}
QLabel#launcherLogo { font-size: 24px; font-weight: 800; color: $accent; }
QLabel#launcherTagline { font-size: 12px; color: $text_dim; }
QLabel#launcherHint { font-size: 11px; color: $text_faint; }
QLabel#launcherHeading {
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.2px;
    color: $text_faint;
}
QListWidget#recentList {
    background-color: transparent;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 4px;
}
QListWidget#recentList::item {
    padding: 8px 10px;
    border-radius: 6px;
    color: $text;
}
QListWidget#recentList::item:selected { background-color: $select; color: $on_select; }

/* ── Dialogs and wizard ────────────────────────────────────────────────── */
QLabel#dialogHeading { font-size: 16px; font-weight: 700; color: $text; }
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
QLabel#stepLabel[state="active"] { color: $accent; font-weight: 700; }
QLabel#stepLabel[state="done"] { color: $ok; }
QLabel#stepCircle {
    border-radius: 13px;
    font-weight: 800;
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
QLabel#wizardTitle { font-size: 18px; font-weight: 800; color: $text; }
QLabel#wizardSubtitle { font-size: 12px; color: $text_dim; }
QLabel#fieldLabel { font-size: 12px; font-weight: 600; color: $text; }
QLabel#fieldHint { font-size: 11px; color: $text_dim; }
QLabel#requiredNote { font-size: 11px; color: $danger; }
QLabel#hintOk { color: $ok; font-size: 12px; }
QLabel#hintWarn { color: $warn; font-size: 12px; }
QLabel#hintError { color: $danger; font-size: 12px; }

/* The wizard's drop zone: one rule per state rather than three inline sheets. */
QWidget#dropZone {
    border: 2px dashed $border_strong;
    border-radius: 12px;
    background-color: $surface;
}
QWidget#dropZone[state="hover"] { border-color: $accent; background-color: $accent_soft; }
QWidget#dropZone[state="loaded"] { border-style: solid; border-color: $ok; background-color: $ok_soft; }
QLabel#dropIcon { font-size: 38px; }
QLabel#dropTitle { font-size: 14px; font-weight: 700; color: $text; }
QLabel#dropSubtitle { font-size: 11px; color: $text_dim; }
QLabel#dropFile { font-size: 12px; font-weight: 700; color: $ok; }
""")


def build(dark: bool = True) -> str:
    """Render the stylesheet for one of the two palettes."""
    tokens = dict(DARK if dark else LIGHT, **_FONTS)
    return _QSS.substitute(tokens)


def palette(dark: bool = True) -> dict:
    """The raw tokens, for the rare place that needs a colour in Python."""
    return dict(DARK if dark else LIGHT)


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
