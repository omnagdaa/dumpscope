"""
The analysis window: plugin ribbon, result tabs, and the case overview.
"""

from __future__ import annotations

import logging
import os
import time

from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QAction, QActionGroup, QColor, QDesktopServices, QFont
from PyQt6.QtWidgets import (
    QApplication, QColorDialog, QDockWidget, QFileDialog, QFontDialog,
    QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMainWindow,
    QMessageBox,
    QPushButton, QScrollArea, QSplitter, QStatusBar, QTextEdit,
    QVBoxLayout, QWidget,
)

from core import settings
from core.case import Case, remember_case
from core.database import Database
from core.plugins import PluginRegistry, build_command_args
from core.os_detect import ImageProbe, ImageProfile
from core.vol_runner import RUN_GATE, RunSpec, VolatilityRunner
from core.hash_worker import FileHasher, HashWorker
from core.insights import missing_inputs as insight_missing_inputs
from core.timeline import missing_inputs as timeline_missing_inputs
from ui.bookmark_dialog import BookmarkDialog
from ui.case_tree import CaseTree
from ui.tag_panel import TagPanel
from ui.plugin_args_dialog import PluginArgsDialog
from ui.notifications import Notifier
from ui.plugin_ribbon import PluginRibbon
from ui.result_panel import ResultPanel
from ui.result_tabs import ResultTabs
from ui.insights_view import InsightsView
from ui.timeline_view import TimelineView
from ui import icons
from ui.theme import (
    BASE_FONT_SIZE, build as build_theme, fonts as theme_fonts, palette, restyle,
    set_fonts,
)

log = logging.getLogger("dumpscope.main_window")

# Glyph name and display name. The badge's colours are chosen by the stylesheet
# from its `os` property, so a theme change repaints it like everything else.
OS_BADGES = {
    "windows": ("window",  "Windows"),
    "linux":   ("penguin", "Linux"),
    "mac":     ("apple",   "macOS"),
}
DEFAULT_OS = "windows"

IMAGE_FILTER = (
    "Memory Images (*.raw *.mem *.vmem *.dmp *.img *.bin *.lime *.core *.vmss *.vmsn);;"
    "All Files (*)"
)


class MainWindow(QMainWindow):
    def __init__(self, case: Case | dict, registry: PluginRegistry | None = None,
                 parent=None):
        super().__init__(parent)
        # A plain dict is still accepted so older entry points keep working.
        self.case = case if isinstance(case, Case) else Case.from_dict(case)
        self.is_dark = self.case.is_dark
        self.registry = registry or PluginRegistry.load()
        # Empty until the probe reports, so the first set_os always builds the
        # ribbon rather than being short-circuited as "already showing that OS".
        self.current_os = ""
        self.profile = ImageProfile()

        self._runners: dict[str, VolatilityRunner] = {}
        self._run_started: dict[str, float] = {}
        self._extract_context: dict[str, dict] = {}
        self._hashers: list[FileHasher] = []
        # The high-water mark of concurrent runs, so a finished batch can
        # report on itself and then reset.
        self._batch_size = 0
        self._panels: dict[str, ResultPanel] = {}
        self._os_probe: ImageProbe | None = None
        self.active_source_id: int | None = None

        self.settings = settings.load()
        set_fonts(self.settings.get("ui_font", ""),
                  self.settings.get("mono_font", ""),
                  int(self.settings.get("font_size") or BASE_FONT_SIZE))
        RUN_GATE.set_limit(self.settings.get("max_parallel_runs", 1))

        self.db = self._open_case_database()
        self._ensure_case_directories()
        self._sync_active_source()

        self._build()
        self.apply_theme()

        self.setWindowTitle(f"DumpScope — {self.case.display_label}")
        self.resize(1480, 900)

        if not self.registry.available:
            self._show_status(
                "volatility3 could not be inspected — plugin arguments are unknown."
            )
        else:
            self._show_status("Ready. Select a plugin to begin analysis.")

        if self.case.image_path:
            QTimer.singleShot(0, self._start_os_probe)

    # ── Case wiring ───────────────────────────────────────────────────────────

    def _open_case_database(self) -> Database | None:
        """
        Attach to the case database, reusing the existing case row.

        Previously every launch inserted a fresh row, so reopening a case
        silently multiplied it and every stored result pointed at whichever
        duplicate was created last.
        """
        if self.case.quick_mode:
            return None
        try:
            db = Database(self.case.directory, self.case.case_name)
            db.attach_case(self.case.to_dict())
            return db
        except Exception as exc:
            log.exception("Could not open the case database")
            QMessageBox.warning(
                self, "Case Database",
                f"The case database could not be opened:\n\n{exc}\n\n"
                "Analysis will run, but results will not be saved.",
            )
            return None

    def _ensure_case_directories(self):
        base = self.case.directory
        # Quick Analysis points at the home folder; seeding it with case
        # folders would litter the examiner's home directory.
        if not base or self.case.quick_mode:
            return
        for sub in ("symbols", "cache", "yara", "exports", "dumps", "reports"):
            try:
                os.makedirs(os.path.join(base, sub), exist_ok=True)
            except OSError as exc:
                log.warning("Could not create %s under %s: %s", sub, base, exc)

    def _sync_active_source(self):
        """
        Point the window at the case's current image, registering it as a data
        source if it is not already one. Called on open and whenever the image
        changes, so results always carry the source they came from.
        """
        if self.db is None or not self.case.image_path:
            return
        self.active_source_id = self.db.add_data_source(
            self.case.image_path, md5=self.case.md5 or "", sha256=self.case.sha256 or ""
        )

    @property
    def dumps_dir(self) -> str:
        """Where extractions land. Empty in Quick Analysis, which has no case."""
        base = self.case.directory
        return os.path.join(base, "dumps") if base else ""

    @property
    def symbol_dirs(self) -> list[str]:
        """
        The case's symbol folder. Quick Analysis has none and uses vol3's own
        locations; its "directory" is only the home folder, and symbols
        written there would end up loose in the examiner's home.
        """
        if self.case.quick_mode or not self.case.directory:
            return []
        return [os.path.join(self.case.directory, "symbols")]

    @property
    def vol_cache_dir(self) -> str:
        if self.case.quick_mode or not self.case.directory:
            return ""
        return os.path.join(self.case.directory, "cache")

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        self._build_menu()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.ribbon = PluginRibbon(self.registry, compact=True)
        self.ribbon.plugin_clicked.connect(self._on_plugin_clicked)
        self.ribbon.theme_toggled.connect(self.toggle_theme)
        self.ribbon.palette_requested.connect(self.open_command_palette)
        root.addWidget(self.ribbon)

        # The OS badge lives in the sidebar, so the sidebar has to exist before
        # anything sets an OS.
        self._build_case_dock()
        self._install_sidebar_toggle()
        # Something has to be on the ribbon before the probe reports, and the
        # probe cannot report at all until an image is loaded.
        self.set_os(DEFAULT_OS, quiet=True)

        self.tabs = ResultTabs()
        self.tabs.tabCloseRequested.connect(self._close_tab)
        # The Case tab is pinned and cannot be closed: it is the case's own
        # surface, not a throwaway result.
        self.tabs.add_result_tab(self._build_overview_tab(), "Case",
                                 closable=False, pinned=True)
        # Timeline and Insights read the stored output and rebuild whenever a
        # run finishes, so they are permanent tabs rather than results.
        self.insights_view = InsightsView()
        self.insights_view.collect_requested.connect(self._collect)
        self.insights_view.bookmark_requested.connect(self._bookmark_insight)
        self.insights_view.finding_activated.connect(
            lambda finding: self._show_plugin_output(finding.plugin))
        self.tabs.add_result_tab(self.insights_view, "Insights",
                                 closable=False, pinned=True)
        self.timeline_view = TimelineView()
        self.timeline_view.collect_requested.connect(self._collect)
        self.timeline_view.event_activated.connect(
            lambda event: self._show_plugin_output(event.plugin))
        self.tabs.add_result_tab(self.timeline_view, "Timeline",
                                 closable=False, pinned=True)
        self.tabs.setCurrentIndex(0)
        self._refresh_image_facts()
        root.addWidget(self.tabs, 1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.notifier = Notifier(
            self, desktop=bool(self.settings.get("desktop_notifications", True)),
        )
        self.notifier.set_dark(self.is_dark)
        self._refresh_analysis_views()

    def _build_case_dock(self):
        """
        The left sidebar: the case header, the case explorer, and the tag index.

        Quick Analysis has no database, so it has no sources, results or tags
        to explore — but it still has an image and a detected OS, so the header
        is built either way and only the navigation below it is conditional.
        """
        container = QWidget()
        container.setObjectName("caseSidebar")
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self._build_case_header())

        if self.db is None:
            self.case_tree = None
            self.tag_panel = None
            column.addStretch(1)
        else:
            self.case_tree = CaseTree()
            self.case_tree.plugin_name = lambda plugin_id: (
                self.registry.get(plugin_id).short_name if self.registry.get(plugin_id)
                else plugin_id.rsplit(".", 1)[-1])
            self.case_tree.source_activated.connect(self._activate_source)
            self.case_tree.source_remove.connect(self._remove_source)
            self.case_tree.source_hash.connect(self._hash_source)
            self.case_tree.add_source.connect(self._open_image_dialog)
            self.case_tree.result_opened.connect(self._open_stored_result)
            self.case_tree.result_deleted.connect(self._delete_stored_result)
            self.case_tree.bookmark_activated.connect(self._show_bookmark)
            self.case_tree.bookmark_deleted.connect(self._delete_bookmark)

            self.tag_panel = TagPanel()
            self.tag_panel.tag_created.connect(self._new_tag)
            self.tag_panel.tag_renamed.connect(self._rename_tag)
            self.tag_panel.tag_recoloured.connect(self._recolour_tag)
            self.tag_panel.tag_deleted.connect(self._delete_tag)
            self.tag_panel.finding_activated.connect(self._goto_finding)
            self.tag_panel.finding_deleted.connect(self._delete_bookmark)
            self.tag_panel.finding_untagged.connect(self._untag_finding)

            # The case explorer and the tag index are both navigation, so they
            # share one sidebar; the splitter lets an examiner give whichever
            # they are living in the room, instead of the layout deciding.
            explorer = QSplitter(Qt.Orientation.Vertical)
            explorer.addWidget(self.case_tree)
            explorer.addWidget(self.tag_panel)
            explorer.setStretchFactor(0, 3)
            explorer.setStretchFactor(1, 2)
            explorer.setChildrenCollapsible(False)
            column.addWidget(explorer, 1)

        dock = QDockWidget("Case", self)
        dock.setObjectName("caseDock")
        dock.setWidget(container)
        dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            # Closable is what enables the dock's toggle action (Ctrl+B); the
            # title bar is hidden, so it adds no close button of its own.
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        # The dock's own title bar would repeat what the case header already
        # says, one line above it.
        dock.setTitleBarWidget(QWidget())
        self.case_dock = dock
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)
        dock.setMinimumWidth(248)
        self._refresh_case_tree()

    def _install_sidebar_toggle(self):
        """
        Ctrl+B, View > Sidebar and the ribbon's sidebar button all hide and
        show the case dock. Qt's own toggle action is used so the three can
        never disagree with the dock, including after it is floated and closed.
        The choice is remembered: an examiner who works full width keeps it.
        """
        action = self.case_dock.toggleViewAction()
        action.setText("Sidebar")
        action.setShortcut("Ctrl+B")
        self.sidebar_action = action
        self.view_menu.insertAction(self.view_menu.actions()[0], action)
        self.view_menu.insertSeparator(self.view_menu.actions()[1])
        self.ribbon.sidebar_btn.clicked.connect(action.trigger)
        self.case_dock.setVisible(bool(self.settings.get("sidebar_visible", True)))
        action.toggled.connect(
            lambda shown: setattr(self, "settings", settings.save(sidebar_visible=shown)))

    def _refresh_case_tree(self):
        if getattr(self, "case_tree", None) is None or self.db is None:
            return
        try:
            bookmarks = self.db.get_bookmarks()
            tags = self.db.get_tags()
            self.case_tree.refresh(
                self.db.get_data_sources(),
                self.db.get_results(),
                bookmarks,
                active_source_id=self.active_source_id,
            )
            if self.tag_panel is not None:
                self.tag_panel.refresh(tags, bookmarks)
            for panel in self._result_panels():
                panel.set_tags(tags)
        except Exception as exc:
            log.warning("Could not refresh the case tree: %s", exc)

    def _result_panels(self) -> list[ResultPanel]:
        """Every open results tab. Empty before the tab bar exists — the case
        dock is built first and refreshes itself on the way up."""
        tabs = getattr(self, "tabs", None)
        if tabs is None:
            return []
        return [
            tabs.widget(i) for i in range(tabs.count())
            if isinstance(tabs.widget(i), ResultPanel)
        ]

    # ── Data sources ──────────────────────────────────────────────────────────

    def _activate_source(self, source_id: int, path: str):
        if not os.path.exists(path):
            QMessageBox.critical(
                self, "Image Missing",
                f"This data source is no longer on disk:\n\n{path}",
            )
            return
        self.active_source_id = source_id
        self.case.image_path = path
        self.case.save()
        self._set_image_label(path)
        self._refresh_evidence()
        self._refresh_case_tree()
        self._refresh_analysis_views()
        self._show_status(f"Active data source: {os.path.basename(path)}")
        self._start_os_probe()

    def _remove_source(self, source_id: int):
        source = self.db.get_data_source(source_id) if self.db else None
        if source is None:
            return
        answer = QMessageBox.question(
            self, "Remove Data Source",
            f"Remove this image from the case?\n\n{source['path']}\n\n"
            "The file itself is not deleted, and results already produced from "
            "it are kept.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.db.remove_data_source(source_id)
        if self.active_source_id == source_id:
            self.active_source_id = None
            self.case.image_path = ""
            self.case.save()
            self._set_image_label("")
        self._refresh_case_tree()
        self._show_status("Data source removed from the case.")

    def _hash_source(self, source_id: int, path: str):
        """Hash an image in the background and record the digests."""
        if not os.path.exists(path):
            QMessageBox.critical(self, "Image Missing", f"Not on disk:\n\n{path}")
            return
        if getattr(self, "_hash_worker", None) is not None:
            self._show_status("A hash is already in progress.")
            return

        self._show_status(f"Hashing {os.path.basename(path)}…")
        worker = HashWorker(path, parent=self)
        worker.progress.connect(
            lambda pct: self._show_status(f"Hashing {os.path.basename(path)} — {pct}%")
        )
        worker.hashes_ready.connect(
            lambda md5, sha256, sid=source_id: self._on_hashes(sid, md5, sha256)
        )
        worker.error.connect(
            lambda message: self._show_status(f"Hashing failed: {message}")
        )
        worker.finished.connect(lambda: setattr(self, "_hash_worker", None))
        self._hash_worker = worker
        worker.start()

    def _on_hashes(self, source_id: int, md5: str, sha256: str):
        if self.db:
            self.db.update_data_source_hashes(source_id, md5, sha256)
        if source_id == self.active_source_id:
            self.case.md5, self.case.sha256 = md5, sha256
            self.case.save()
            self._refresh_evidence()
        self._refresh_case_tree()
        self._show_status(f"Hashed — MD5 {md5[:16]}…")
        self.notifier.notify(
            "Hashing finished", f"MD5 {md5[:16]}…  ·  SHA-256 {sha256[:16]}…",
            "success",
        )

    # ── Stored results and bookmarks ──────────────────────────────────────────

    def _open_stored_result(self, result_id: int):
        """Reopen a saved run in a read-only tab, without re-running anything."""
        stored = self.db.load_result(result_id) if self.db else None
        if stored is None:
            QMessageBox.warning(self, "Result Missing",
                                "That stored result could not be read.")
            return

        plugin = stored["plugin"]
        short = plugin.rsplit(".", 1)[-1]
        panel = ResultPanel(short, plugin)
        self._wire_panel(panel)
        panel.set_columns(stored["columns"])
        panel.append_rows(stored["rows"])
        panel.set_finished(0)
        panel.append_log(f"Stored result from {stored.get('created_at', 'an earlier run')}.")

        index = self.tabs.add_result_tab(panel, f"{short} (saved)")
        self.tabs.setCurrentIndex(index)
        n = len(stored["rows"])
        self._show_status(f"Opened stored {short}: {n:,} {'row' if n == 1 else 'rows'}.")

    def _delete_stored_result(self, result_id: int):
        answer = QMessageBox.question(
            self, "Delete Result",
            "Delete this stored result from the case?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes or self.db is None:
            return
        self.db.delete_result(result_id)
        self._refresh_case_tree()
        self._refresh_analysis_views()
        self._show_status("Stored result deleted.")

    def _show_bookmark(self, bookmark: dict):
        details = [f"Plugin: {bookmark.get('artifact_type') or '—'}"]
        if bookmark.get("tag"):
            details.append(f"Tag: {bookmark['tag']}")
        if bookmark.get("source_name"):
            details.append(f"Source: {bookmark['source_name']}")
        if bookmark.get("notes"):
            details.append(f"Notes: {bookmark['notes']}")
        if bookmark.get("created_at"):
            details.append(f"Added: {bookmark['created_at']}")
        details.append("")
        details.append(bookmark.get("description") or "")
        QMessageBox.information(
            self, bookmark.get("label") or "Bookmark", "\n".join(details)
        )

    def _delete_bookmark(self, bookmark_id: int):
        if self.db is None:
            return
        self.db.delete_bookmark(bookmark_id)
        self._refresh_case_tree()
        self._show_status("Bookmark deleted.")

    def _build_menu(self):
        bar = self.menuBar()

        file_menu = bar.addMenu("&File")
        open_action = QAction("Open Image…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_image_dialog)
        file_menu.addAction(open_action)
        file_menu.addSeparator()

        export_action = QAction("Export Current Results…", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self._export_current)
        file_menu.addAction(export_action)

        report_action = QAction("Generate Case Report…", self)
        report_action.setShortcut("Ctrl+R")
        report_action.triggered.connect(self._generate_report)
        file_menu.addAction(report_action)


        close_case_action = QAction("Close Case", self)
        close_case_action.setShortcut("Ctrl+W")
        close_case_action.triggered.connect(self._close_case)
        file_menu.addAction(close_case_action)
        file_menu.addSeparator()

        quit_action = QAction("Exit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        palette_action = QAction("Command Palette…", self)
        palette_action.setShortcut("Ctrl+Shift+P")
        palette_action.triggered.connect(self.open_command_palette)
        file_menu.insertAction(file_menu.actions()[0], palette_action)
        file_menu.insertSeparator(file_menu.actions()[1])

        view_menu = bar.addMenu("&View")
        self.view_menu = view_menu
        theme_action = QAction("Toggle Theme", self)
        theme_action.setShortcut("Ctrl+T")
        theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(theme_action)

        search_action = QAction("Search Plugins", self)
        search_action.setShortcut("Ctrl+P")
        search_action.triggered.connect(lambda: self.ribbon.focus_search())
        view_menu.addAction(search_action)

        view_menu.addSeparator()
        font_action = QAction("Interface Font…", self)
        font_action.triggered.connect(self._choose_ui_font)
        view_menu.addAction(font_action)

        mono_action = QAction("Monospace Font…", self)
        mono_action.triggered.connect(self._choose_mono_font)
        view_menu.addAction(mono_action)

        reset_fonts = QAction("Reset Fonts", self)
        reset_fonts.triggered.connect(self._reset_fonts)
        view_menu.addAction(reset_fonts)

        self.notify_action = QAction("Desktop Notifications", self)
        self.notify_action.setCheckable(True)
        self.notify_action.setChecked(
            bool(self.settings.get("desktop_notifications", True)))
        self.notify_action.toggled.connect(self._set_desktop_notifications)
        view_menu.addAction(self.notify_action)
        view_menu.addSeparator()

        identify_action = QAction("Re-identify Image", self)
        identify_action.triggered.connect(self._start_os_probe)
        view_menu.addAction(identify_action)
        view_menu.addSeparator()

        # Detection can be overridden: an examiner who knows what the image is
        # should not have to wait for a scan to agree with them.
        for os_name in ("windows", "linux", "mac"):
            action = QAction(f"Show {OS_BADGES[os_name][1]} Plugins", self)
            action.triggered.connect(lambda _, name=os_name: self.set_os(name, manual=True))
            view_menu.addAction(action)

        tools_menu = bar.addMenu("&Tools")
        symbols_action = QAction("Symbols && YARA…", self)
        symbols_action.triggered.connect(self._open_symbol_manager)
        tools_menu.addAction(symbols_action)

        creds_action = QAction("Extract Credentials", self)
        creds_action.triggered.connect(self._sweep_credentials)
        tools_menu.addAction(creds_action)

        refresh_action = QAction("Refresh Plugin List", self)
        refresh_action.triggered.connect(self._refresh_registry)
        tools_menu.addAction(refresh_action)
        tools_menu.addSeparator()

        # One at a time is the safe default (shared vol3 cache, memory per
        # process); an examiner on a large machine can raise it.
        parallel_menu = tools_menu.addMenu("Parallel volatility3 Runs")
        self.parallel_group = QActionGroup(self)
        self.parallel_group.setExclusive(True)
        current = RUN_GATE.limit
        for count in (1, 2, 3, 4):
            label = "1 (one at a time, safest)" if count == 1 else str(count)
            action = QAction(label, self, checkable=True)
            action.setData(count)
            action.setChecked(count == current)
            action.triggered.connect(lambda _, n=count: self._set_parallel_runs(n))
            self.parallel_group.addAction(action)
            parallel_menu.addAction(action)

        help_menu = bar.addMenu("&Help")
        about_action = QAction("About DumpScope", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _build_case_header(self) -> QWidget:
        """
        Who and what, at the top of the sidebar: the case, the image it is
        working on, and what that image turned out to be.

        These three facts used to sit in a title bar beside the product name.
        They belong here — the sidebar is where the case is navigated, so the
        case identifies itself at the head of it.
        """
        header = QWidget()
        header.setObjectName("caseHeader")
        column = QVBoxLayout(header)
        column.setContentsMargins(12, 10, 10, 10)
        column.setSpacing(5)

        title_row = QHBoxLayout()
        title_row.setSpacing(7)
        self.os_glyph = QLabel()
        self.os_glyph.setObjectName("osGlyph")
        self.os_glyph.setFixedWidth(18)
        self.case_tag = QLabel(self.case.case_name)
        self.case_tag.setObjectName("caseNameLabel")
        self.case_tag.setWordWrap(True)
        title_row.addWidget(self.os_glyph, 0, Qt.AlignmentFlag.AlignTop)
        title_row.addWidget(self.case_tag, 1)

        self.image_lbl = QLabel()
        self.image_lbl.setObjectName("imageLabel")
        self.image_lbl.setProperty("loaded", "false")
        self._set_image_label(self.case.image_path)

        self.os_badge = QLabel()
        self.os_badge.setObjectName("osBadge")

        badge_row = QHBoxLayout()
        badge_row.setSpacing(6)
        badge_row.addWidget(self.os_badge)
        badge_row.addStretch()

        column.addLayout(title_row)
        column.addWidget(self.image_lbl)
        column.addLayout(badge_row)

        self._update_os_badge()
        return header

    def _build_overview_tab(self) -> QWidget:
        """
        The Case tab: the case's own details, the evidence, and what the probe
        made of it — editable in place.

        Collecting these in a wizard before the case opened meant describing an
        image nobody had looked at yet, in a window that then went away. They
        belong here, beside the evidence they describe, editable at any point in
        the investigation.
        """
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(14)

        layout.addWidget(self._build_case_details())
        layout.addWidget(self._build_evidence_group())

        self.profile_group = QGroupBox("Image Profile")
        self.profile_grid = QGridLayout(self.profile_group)
        self.profile_grid.setSpacing(8)
        self.profile_grid.setColumnStretch(1, 1)
        self.profile_grid.setColumnStretch(3, 1)
        layout.addWidget(self.profile_group)

        layout.addStretch()
        area.setWidget(inner)
        return area

    def _build_case_details(self) -> QWidget:
        group = QGroupBox("Case Details")
        grid = QGridLayout(group)
        grid.setSpacing(8)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.case_fields: dict[str, QLineEdit] = {}
        editable = (
            ("case_name",     "Case Name",   "A short name for the investigation"),
            ("case_number",   "Case Number", "Your reference, e.g. INC-2026-014"),
            ("examiner_name", "Examiner",    "Who is doing the work"),
            ("examiner_id",   "Examiner ID", "Badge or staff number"),
            ("organization",  "Organisation", ""),
            ("examiner_email", "Email",      ""),
        )
        for index, (attr, label, hint) in enumerate(editable):
            row, column = divmod(index, 2)
            name = QLabel(label)
            name.setObjectName("fieldLabel")
            field = QLineEdit(str(getattr(self.case, attr, "") or ""))
            field.setPlaceholderText(hint)
            field.editingFinished.connect(
                lambda a=attr, f=field: self._commit_case_field(a, f.text())
            )
            self.case_fields[attr] = field
            grid.addWidget(name, row, column * 2)
            grid.addWidget(field, row, column * 2 + 1)

        row = len(editable) // 2
        notes_label = QLabel("Notes")
        notes_label.setObjectName("fieldLabel")
        self.notes_edit = QTextEdit(self.case.notes or "")
        self.notes_edit.setPlaceholderText("Scope, authorisation, working hypotheses…")
        self.notes_edit.setFixedHeight(72)
        # A QTextEdit has no editingFinished; commit when focus leaves it.
        self.notes_edit.focusOutEvent = self._wrap_focus_out(self.notes_edit)
        grid.addWidget(notes_label, row, 0)
        grid.addWidget(self.notes_edit, row, 1, 1, 3)

        folder_label = QLabel("Folder")
        folder_label.setObjectName("fieldLabel")
        folder_row = QHBoxLayout()
        folder_row.setSpacing(6)
        self.folder_value = QLabel(self.case.directory or "Quick Analysis — nothing is saved")
        self.folder_value.setObjectName("fieldHint")
        self.folder_value.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        reveal = QPushButton("Open Folder")
        reveal.setFixedHeight(24)
        reveal.setEnabled(bool(self.case.directory))
        reveal.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.case.directory))
        )
        folder_row.addWidget(self.folder_value, 1)
        folder_row.addWidget(reveal)
        grid.addWidget(folder_label, row + 1, 0)
        grid.addLayout(folder_row, row + 1, 1, 1, 3)

        if self.case.quick_mode:
            for field in self.case_fields.values():
                field.setReadOnly(True)
            self.notes_edit.setReadOnly(True)
        return group

    def _wrap_focus_out(self, widget):
        original = type(widget).focusOutEvent

        def handler(event, _widget=widget):
            original(_widget, event)
            self._commit_case_field("notes", _widget.toPlainText())
        return handler

    def _commit_case_field(self, attr: str, value: str):
        """Write one edited field through to the case file and the database."""
        value = value.strip()
        if str(getattr(self.case, attr, "") or "") == value:
            return
        if attr == "case_name" and not value:
            self.case_fields[attr].setText(self.case.case_name)
            return

        setattr(self.case, attr, value)
        try:
            self.case.save()
        except Exception as exc:
            log.warning("Could not save the case: %s", exc)
            self._show_status(f"Could not save: {exc}")
            return

        if self.db is not None:
            try:
                self.db.attach_case(self.case.to_dict())
                self.db.log_action("case_edited", f"{attr} = {value}",
                                   self.case.examiner_name)
            except Exception as exc:
                log.warning("Could not record the case edit: %s", exc)

        if attr == "case_name":
            self.case_tag.setText(value)
            self.setWindowTitle(f"DumpScope — {self.case.display_label}")
        self._show_status(f"Saved {attr.replace('_', ' ')}.")

    def _build_evidence_group(self) -> QWidget:
        group = QGroupBox("Evidence")
        grid = QGridLayout(group)
        grid.setSpacing(8)
        grid.setColumnStretch(1, 1)

        image_row = QHBoxLayout()
        image_row.setSpacing(6)
        self.evidence_lbl = QLabel()
        self.evidence_lbl.setObjectName("fieldHint")
        self.evidence_lbl.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        change_btn = QPushButton("Load Image…")
        change_btn.setFixedHeight(24)
        change_btn.clicked.connect(self._open_image_dialog)
        self.hash_btn = QPushButton("Compute Hashes")
        self.hash_btn.setFixedHeight(24)
        self.hash_btn.clicked.connect(self._hash_active_source)
        image_row.addWidget(self.evidence_lbl, 1)
        image_row.addWidget(change_btn)
        image_row.addWidget(self.hash_btn)

        name = QLabel("Image")
        name.setObjectName("fieldLabel")
        grid.addWidget(name, 0, 0)
        grid.addLayout(image_row, 0, 1)

        self.hash_fields: dict[str, QLineEdit] = {}
        for index, (label, key) in enumerate((("MD5", "md5"), ("SHA-256", "sha256"))):
            caption = QLabel(label)
            caption.setObjectName("fieldLabel")
            value = QLineEdit(getattr(self.case, key, "") or "")
            value.setPlaceholderText("not computed")
            value.setReadOnly(True)
            self.hash_fields[key] = value
            grid.addWidget(caption, index + 1, 0)
            grid.addWidget(value, index + 1, 1)

        self._refresh_evidence()
        return group

    def _refresh_evidence(self):
        path = self.case.image_path
        if not path:
            self.evidence_lbl.setText("No image loaded")
        else:
            self.evidence_lbl.setText(f"{path}    ·    {_format_size(path)}")
        self.hash_btn.setEnabled(bool(path) and os.path.exists(path))
        for key, field in getattr(self, "hash_fields", {}).items():
            field.setText(getattr(self.case, key, "") or "")

    def _hash_active_source(self):
        if self.active_source_id is None or not self.case.image_path:
            self._show_status("Load an image first.")
            return
        self._hash_source(self.active_source_id, self.case.image_path)

    def _refresh_image_facts(self):
        """
        Redraw the Image Profile card from the current probe result.

        The grid is rebuilt rather than updated in place: the set of facts
        volatility3 returns differs between images, so there is no fixed set of
        rows to keep around.
        """
        grid = getattr(self, "profile_grid", None)
        if grid is None:
            return
        while grid.count():
            item = grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        facts: list[tuple[str, str]] = []
        if self.profile.os:
            facts.append(("Operating System", self.profile.summary()))
        if self.profile.container:
            facts.append(("Container", self.profile.container))
        facts.extend(self.profile.details.items())

        if not facts:
            placeholder = QLabel(
                "Load an image to identify it."
                if not self.case.image_path else
                "Identifying the image…"
            )
            placeholder.setObjectName("overviewBlurb")
            grid.addWidget(placeholder, 0, 0, 1, 4)
            return

        # Two label/value pairs per row; long values still get the full width.
        for index, (label, value) in enumerate(facts):
            row, column = divmod(index, 2)
            name = QLabel(label)
            name.setObjectName("fieldLabel")
            field = QLabel(str(value))
            field.setObjectName("fieldValue")
            field.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            field.setWordWrap(True)
            grid.addWidget(name, row, column * 2)
            grid.addWidget(field, row, column * 2 + 1)

        self._refresh_evidence()

    # ── OS handling ───────────────────────────────────────────────────────────

    def _start_os_probe(self):
        """
        Identify the loaded image and scope the ribbon to it.

        Runs in two stages. The header sniff comes back almost immediately and
        is acted on straight away, so an examiner opening a crash dump sees the
        right plugin set before volatility3 has even started; the full profile
        arrives afterwards and fills in the build details.
        """
        image_path = self.case.image_path
        if not image_path or not os.path.exists(image_path):
            return
        if self._os_probe is not None:
            self._os_probe.cancel()
            self._os_probe.wait(2000)

        self._set_badge_probing()
        self._show_status("Identifying the image…")

        probe = ImageProbe(image_path, self.symbol_dirs, parent=self,
                           cache_dir=self.vol_cache_dir)
        probe.sniffed.connect(self._on_sniffed)
        probe.profiled.connect(self._on_profiled)
        probe.note.connect(self._show_status)
        probe.finished.connect(lambda: setattr(self, "_os_probe", None))
        self._os_probe = probe
        probe.start()

    def _on_sniffed(self, profile: ImageProfile):
        """The instant verdict from the file header, before vol3 has run."""
        if profile.os:
            self.profile = profile
            self.set_os(profile.os)
            self._show_status(f"{profile.summary()} — confirming…")
        elif profile.container:
            self._show_status(
                f"{profile.container} — identifying the operating system…"
            )

    def _on_profiled(self, profile: ImageProfile):
        """The final verdict, with whatever detail volatility3 could give."""
        self.profile = profile
        if profile.os:
            self.set_os(profile.os)
        # set_os is a no-op when the sniff already chose this OS, so the badge
        # is refreshed unconditionally — otherwise it stays on "Identifying…".
        self._update_os_badge()
        self._refresh_image_facts()
        if profile.confidence == "assumed":
            self._show_status(
                f"{profile.summary()}. Pick another OS under View if that is wrong."
            )
        else:
            self._show_status(
                f"{profile.summary()} — {self.ribbon.plugin_count()} plugins available."
            )
        if self.db and self.active_source_id and profile.os:
            try:
                self.db.add_data_source(self.case.image_path, os_hint=profile.os)
                self._refresh_case_tree()
            except Exception as exc:
                log.debug("Could not record the detected OS: %s", exc)

    def set_os(self, os_name: str, manual: bool = False, quiet: bool = False):
        """Scope the ribbon to `os_name`. Cheap and idempotent."""
        if os_name not in OS_BADGES or os_name == self.current_os:
            return
        self.current_os = os_name
        _icon, label = OS_BADGES[os_name]
        self.ribbon.set_os(os_name, label)
        self._update_os_badge()
        if manual:
            # A manual choice is a decision, not a detection; record it as one
            # so the overview does not claim volatility3 concluded it.
            self.profile = ImageProfile(
                os=os_name, confidence="likely", method="chosen manually",
                container=self.profile.container, details=self.profile.details,
            )
            self._refresh_image_facts()
        if quiet:
            return
        self._show_status(
            f"Showing {label} plugins — {self.ribbon.plugin_count()} available."
        )

    def _set_badge_probing(self):
        # No setPixmap here: a QLabel shows a pixmap *or* text, and handing it
        # even a null pixmap drops the text it was showing.
        self.os_badge.setText("Identifying…")
        self.os_badge.setProperty("os", "")
        self.os_badge.setProperty("probing", "true")
        restyle(self.os_badge)

    def _update_os_badge(self):
        if not self.current_os:
            self._set_badge_probing()
            return
        glyph, label = OS_BADGES[self.current_os]
        suffix = "?" if self.profile.confidence == "assumed" else ""
        self.os_badge.setText(f"{label}{suffix}")
        self.os_badge.setToolTip(self.profile.summary() or f"{label} plugins")
        self.os_badge.setProperty("os", self.current_os)
        self.os_badge.setProperty("probing", "false")
        restyle(self.os_badge)
        # The badge's own colour comes from the stylesheet, so the glyph beside
        # it has to be re-inked from the palette by hand.
        tokens = palette(dark=self.is_dark)
        self.os_glyph.setPixmap(icons.pixmap(
            glyph, size=14,
            color={"windows": tokens["accent"], "linux": tokens["ok"],
                   "mac": tokens["warn"]}[self.current_os],
            ratio=self.devicePixelRatioF() or 1.0,
        ))

    # ── Plugin execution ──────────────────────────────────────────────────────

    def _on_plugin_clicked(self, plugin_id: str):
        image_path = self.case.image_path
        if not image_path:
            QMessageBox.warning(
                self, "No Image Loaded",
                "Load a memory image first (File → Open Image).",
            )
            return
        if not os.path.exists(image_path):
            QMessageBox.critical(
                self, "Image Missing",
                f"The image is no longer at:\n\n{image_path}",
            )
            return
        if plugin_id in self._runners:
            self._focus_panel(plugin_id)
            return

        info = self.registry.get(plugin_id)
        if info is None:
            QMessageBox.warning(self, "Unknown Plugin",
                                f"{plugin_id} is not available in this volatility3.")
            return

        extra_args: list[str] = []
        if info.needs_input or info.optional_args:
            if info.needs_input:
                dialog = PluginArgsDialog(info, parent=self)
                if dialog.exec() != PluginArgsDialog.DialogCode.Accepted:
                    return
                extra_args = build_command_args(info, dialog.values())
            else:
                extra_args = self._default_args_for(info)

        self._launch(info, extra_args)

    def _default_args_for(self, info) -> list[str]:
        """Arguments applied automatically for plugins that benefit from them."""
        if info.id.endswith("yarascan.YaraScan"):
            rules = self._yara_rule_files()
            if rules:
                # vol3 takes a single rules file; the first is used and the rest
                # are reported so the choice is never silent.
                return ["--yara-file", rules[0]]
        return []

    def _yara_rule_files(self) -> list[str]:
        base = self.case.directory
        directory = os.path.join(base, "yara") if base else ""
        if not directory or not os.path.isdir(directory):
            return []
        return sorted(
            os.path.join(directory, name)
            for name in os.listdir(directory)
            if name.lower().endswith((".yar", ".yara", ".rule", ".rules"))
        )

    def _launch(self, info, extra_args: list[str]):
        panel = ResultPanel(info.short_name, info.id)
        panel.cancel_requested.connect(lambda key=info.id: self._cancel_run(key))
        self._wire_panel(panel)

        index = self.tabs.add_result_tab(panel, info.short_name)
        self.tabs.setCurrentIndex(index)
        self._panels[info.id] = panel
        panel.set_running(True)
        self.ribbon.set_running(info.id, True)

        spec = RunSpec(
            image_path=self.case.image_path,
            plugin_id=info.id,
            symbol_dirs=self.symbol_dirs,
            cache_dir=self.vol_cache_dir,
            extra_args=extra_args,
            output_dir=self.dumps_dir,
        )
        self._start_runner(info.id, spec, panel)
        log.info("Started %s %s", info.id, " ".join(extra_args))
        self._show_status(f"Running {info.short_name}…")

    def _start_runner(self, run_key: str, spec: RunSpec, panel: ResultPanel):
        """
        Attach a runner to a panel.

        Keyed by `run_key` rather than by plugin id, because an extraction runs
        the same plugin as the listing it was started from — keying by plugin
        would make "dump PID 4" and the pslist tab it came from the same run,
        and cancelling either would stop the other.
        """
        panel.run_key = run_key
        runner = VolatilityRunner(spec, parent=self)
        runner.columns_ready.connect(panel.set_columns)
        runner.rows_ready.connect(panel.append_rows)
        runner.progress.connect(panel.set_progress)
        runner.log_line.connect(panel.append_log)
        runner.queued.connect(panel.set_queued)
        runner.failed.connect(panel.set_error)
        runner.run_finished.connect(
            lambda code, key=run_key: self._on_run_finished(code, key)
        )
        # Finished QThread objects are parented to the window and would
        # otherwise pile up for the life of the session, one per run.
        runner.finished.connect(runner.deleteLater)
        self._runners[run_key] = runner
        self._batch_size = max(self._batch_size, len(self._runners))
        self._run_started[run_key] = time.monotonic()
        runner.start()

    def _cancel_run(self, plugin_id: str):
        runner = self._runners.get(plugin_id)
        if runner:
            runner.cancel()
            self._show_status(f"Stopping {plugin_id}…")

    def _on_run_finished(self, exit_code: int, run_key: str):
        runner = self._runners.pop(run_key, None)
        panel = self._panels.get(run_key)
        cancelled = bool(runner and runner.cancelled)
        plugin_id = panel.plugin_id if panel else run_key
        is_extraction = "#dump" in run_key

        if panel:
            panel.set_finished(exit_code, cancelled=cancelled)
            # An extraction's table is a manifest of files vol3 wrote, not an
            # analysis of the image; storing it as one would put a second,
            # misleading "pslist" result in the case.
            if self.db and exit_code == 0 and not cancelled and not is_extraction:
                try:
                    self.db.save_analysis(plugin_id, panel.result_payload(),
                                          source_id=self.active_source_id)
                except Exception as exc:
                    log.warning("Could not store results for %s: %s", plugin_id, exc)

        self.ribbon.set_running(plugin_id, False)
        self._refresh_case_tree()
        if exit_code == 0 and not cancelled and not is_extraction:
            self._refresh_analysis_views()

        rows = panel.model.rowCount() if panel else 0
        short = plugin_id.rsplit(".", 1)[-1]
        elapsed = self._elapsed(run_key)

        if is_extraction:
            written = self._record_extraction(run_key)
            if exit_code == 0 and not cancelled:
                message = (
                    f"{len(written)} file(s) written to {self.dumps_dir}"
                    if written else
                    "volatility3 reported success but wrote no files."
                )
                self._show_status(f"Extraction finished — {message}")
                self.notifier.notify(
                    "Extraction finished", message,
                    "success" if written else "warning",
                )
                self._announce_idle()
                return

        if cancelled:
            self._show_status(f"{short} cancelled.")
        elif exit_code == 0:
            self._show_status(f"{short} finished: {rows:,} {'row' if rows == 1 else 'rows'}.")
            # Inside a batch (Collect, credential sweep, several clicks) each
            # success would stack a toast over the work; the batch is announced
            # once when it ends. Failures are always announced.
            if self._batch_size < 2:
                self.notifier.notify(
                    f"{short} finished", f"{rows:,} rows{elapsed}", "success")
        else:
            self._show_status(f"{short} failed (exit {exit_code}). See the Log tab.")
            self.notifier.notify(
                f"{short} failed",
                f"Exit code {exit_code}{elapsed} — see the Log tab.", "error",
            )
        self._announce_idle()

    def _elapsed(self, run_key: str) -> str:
        """" — 1m 12s", or nothing if the run was never timed."""
        started = self._run_started.pop(run_key, None)
        if started is None:
            return ""
        seconds = int(time.monotonic() - started)
        if seconds < 60:
            return f" in {seconds}s"
        return f" in {seconds // 60}m {seconds % 60:02d}s"

    def _announce_idle(self):
        """
        Report the batch, once, when the last run of it finishes.

        An examiner who queues six plugins wants to know when the *set* is
        done; six separate "finished" messages do not answer that question,
        and the sixth overwrites the answer in the status bar.
        """
        if self._runners or self._batch_size < 2:
            return
        total = sum(panel.model.rowCount() for panel in self._result_panels())
        self.notifier.notify(
            f"All {self._batch_size} plugins finished",
            f"{total:,} rows across {self._batch_size} runs.", "success",
        )
        self._batch_size = 0

    def _focus_panel(self, plugin_id: str):
        panel = self._panels.get(plugin_id)
        if panel is None:
            return
        index = self.tabs.indexOf(panel)
        if index >= 0:
            self.tabs.setCurrentIndex(index)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_image_dialog(self):
        start_dir = self.case.directory or os.path.expanduser("~")
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Memory Image", start_dir, IMAGE_FILTER
        )
        if not path:
            return
        self.load_image(path)

    def load_image(self, path: str):
        """Make `path` the active image, recording it against the case."""
        self.case.image_path = path
        self.case.md5 = ""
        self.case.sha256 = ""
        self.case.save()
        self._set_image_label(path)
        if self.db:
            try:
                self.db.update_case_image(path)
                self._sync_active_source()
            except Exception as exc:
                log.warning("Could not record the image path: %s", exc)
        self._refresh_case_tree()
        self._refresh_evidence()
        self._show_status(f"Loaded {os.path.basename(path)}")
        self._start_os_probe()

    def _set_image_label(self, path: str):
        self.image_lbl.setText(os.path.basename(path) if path else "No image loaded")
        self.image_lbl.setToolTip(path)
        self.image_lbl.setProperty("loaded", "true" if path else "false")
        restyle(self.image_lbl)

    def _export_current(self):
        panel = self.tabs.currentWidget()
        if not isinstance(panel, ResultPanel):
            QMessageBox.information(
                self, "Nothing to Export",
                "Switch to a results tab before exporting.",
            )
            return
        base = self.case.directory
        panel.export_dialog(os.path.join(base, "exports") if base else "")

    def _save_bookmark(self, payload: dict):
        if not self.db:
            QMessageBox.information(
                self, "No Case Database",
                "Bookmarks belong to a case. Quick Analysis keeps nothing — "
                "create a case to record findings.",
            )
            return

        plugin = payload.pop("__plugin__", "")
        dialog = BookmarkDialog(payload, plugin, self.db.get_tags(), parent=self)
        if dialog.exec() != BookmarkDialog.DialogCode.Accepted:
            return
        values = dialog.values()

        description = "\n".join(
            f"{key}: {value}" for key, value in payload.items() if value
        )
        try:
            self.db.save_bookmark(
                label=values["label"], description=description,
                artifact_type=plugin, tag=values["tag"], notes=values["notes"],
                source_id=self.active_source_id,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Bookmark Failed", str(exc))
            return
        self._refresh_case_tree()
        self._show_status(f"Bookmarked: {values['label']}")

    def _wire_panel(self, panel: ResultPanel):
        """Connect a results tab to the case: bookmarks, tags and extraction."""
        panel.bookmark_requested.connect(self._save_bookmark)
        panel.tag_requested.connect(self._apply_tag)
        panel.dump_requested.connect(self._extract)
        if self.db is not None:
            panel.set_tags(self.db.get_tags())

    # ── Tags ──────────────────────────────────────────────────────────────────

    def _apply_tag(self, payload: dict):
        """
        Attach a tag to the output line the examiner right-clicked.

        The whole row is stored alongside the tag, which is what makes the tag
        navigable later: the row can be found again by its values even after
        the table has been sorted or the plugin re-run.
        """
        if self.db is None:
            QMessageBox.information(
                self, "No Case Database",
                "Tags belong to a case. Quick Analysis keeps nothing — create a "
                "case to record findings.",
            )
            return

        name = payload.pop("__tag__", "")
        plugin = payload.pop("__plugin__", "")
        column = payload.pop("__column__", "")
        cell = payload.pop("__cell__", "")

        if not name:
            name = self._new_tag(return_name=True)
            if not name:
                return

        label = _row_label(payload) or cell or "(row)"
        description = "\n".join(f"{k}: {v}" for k, v in payload.items() if v)
        try:
            self.db.save_bookmark(
                label=label, description=description, artifact_type=plugin,
                tag=name, notes="", source_id=self.active_source_id,
                row=payload, cell_column=column, cell_value=cell,
            )
        except Exception as exc:
            QMessageBox.warning(self, "Tag Failed", str(exc))
            return
        self._refresh_case_tree()
        self._show_status(f"Tagged as {name}: {label}")

    def _new_tag(self, return_name: bool = False):
        if self.db is None:
            return "" if return_name else None
        name, ok = QInputDialog.getText(self, "New Tag", "Tag name:")
        name = name.strip() if ok else ""
        if not name:
            return "" if return_name else None
        colour = QColorDialog.getColor(
            QColor(palette(dark=self.is_dark)["accent"]), self,
            f"Colour for “{name}”",
        )
        self.db.add_tag(name, colour.name() if colour.isValid()
                        else palette(dark=self.is_dark)["accent"])
        self._refresh_case_tree()
        self._show_status(f"Tag “{name}” added.")
        return name if return_name else None

    def _rename_tag(self, old_name: str):
        if self.db is None:
            return
        new_name, ok = QInputDialog.getText(
            self, "Rename Tag", "New name:", text=old_name
        )
        if not ok or not new_name.strip():
            return
        if not self.db.rename_tag(old_name, new_name.strip()):
            QMessageBox.warning(
                self, "Rename Failed",
                f"“{new_name.strip()}” already exists. Merging two tags is a "
                "different decision from renaming one, so it is not done "
                "automatically.",
            )
            return
        self._refresh_case_tree()
        self._show_status(f"Tag renamed to {new_name.strip()}.")

    def _recolour_tag(self, name: str):
        if self.db is None:
            return
        current = next((t for t in self.db.get_tags() if t["name"] == name), None)
        colour = QColorDialog.getColor(
            QColor((current or {}).get("color") or palette(dark=self.is_dark)["accent"]),
            self, f"Colour for “{name}”",
        )
        if colour.isValid():
            self.db.set_tag_color(name, colour.name())
            self._refresh_case_tree()

    def _delete_tag(self, name: str):
        if self.db is None:
            return
        count = self.db.tag_counts().get(name, 0)
        box = QMessageBox(self)
        box.setWindowTitle("Delete Tag")
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(f"Delete the tag “{name}”?")
        box.setInformativeText(
            f"{count} finding(s) carry it."
            if count else "Nothing is tagged with it."
        )
        keep = box.addButton("Delete Tag, Keep Findings",
                             QMessageBox.ButtonRole.AcceptRole)
        purge = box.addButton("Delete Both", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()

        clicked = box.clickedButton()
        if clicked is keep:
            self.db.delete_tag(name, delete_findings=False)
        elif clicked is purge:
            self.db.delete_tag(name, delete_findings=True)
        else:
            return
        self._refresh_case_tree()
        self._show_status(f"Tag “{name}” deleted.")

    def _untag_finding(self, bookmark_id: int):
        if self.db is None:
            return
        self.db.update_bookmark(bookmark_id, tag="")
        self._refresh_case_tree()

    def _goto_finding(self, finding: dict):
        """
        Follow a tag back to the output line it was taken from.

        The tab is opened from the stored result if it is not already open, so
        a tag recorded in an earlier session still leads somewhere without
        re-running the plugin.
        """
        plugin = finding.get("artifact_type") or ""
        row = finding.get("row") or {}
        panel = self._panel_for(plugin)

        if panel is None and self.db is not None:
            stored = next(
                (r for r in self.db.get_results() if r["plugin"] == plugin), None
            )
            if stored is not None:
                self._open_stored_result(stored["id"])
                panel = self._panel_for(plugin)

        if panel is None:
            QMessageBox.information(
                self, "Result Not Open",
                f"Nothing from {plugin.rsplit('.', 1)[-1] or 'that plugin'} is "
                "open, and the case has no saved run of it. Run it again to "
                "follow this tag.",
            )
            return

        self.tabs.setCurrentWidget(panel)
        if panel.select_row(row):
            self._show_status(f"{finding.get('label', 'Finding')} — located.")
        else:
            self._show_status(
                f"{finding.get('label', 'That finding')} is not in the current "
                f"{plugin.rsplit('.', 1)[-1]} output — the image or the plugin "
                "version may differ."
            )

    def _panel_for(self, plugin: str) -> ResultPanel | None:
        for panel in self._result_panels():
            if panel.plugin_id == plugin:
                return panel
        return None

    #: The registry- and memory-derived credential plugins, run together by the
    #: credential sweep. Each is skipped silently if this volatility3 lacks it,
    #: so a partial installation still runs what it has.
    _CREDENTIAL_PLUGINS = (
        "windows.hashdump.Hashdump",
        "windows.lsadump.Lsadump",
        "windows.cachedump.Cachedump",
    )

    def _sweep_credentials(self):
        """
        Run every credential plugin at once, and offer to dump lsass memory.

        hashdump reads the NTLM hashes out of the SAM, lsadump the LSA secrets,
        cachedump the cached domain logons. None of them recovers a plaintext
        password — that comes from cracking the hashes, or from running a
        dumped lsass through pypykatz — so the status makes that explicit rather
        than implying passwords fall out of a button.
        """
        if not self.case.image_path or not os.path.exists(self.case.image_path):
            QMessageBox.warning(self, "No Image Loaded",
                                "Load a Windows memory image first.")
            return
        if self.current_os != "windows":
            QMessageBox.information(
                self, "Windows Only",
                "The credential plugins read Windows registry and LSASS "
                "structures; they do not apply to this image.",
            )
            return

        available = [pid for pid in self._CREDENTIAL_PLUGINS
                     if self.registry.get(pid) is not None]
        if not available:
            QMessageBox.warning(
                self, "Credential Plugins Missing",
                "This volatility3 has none of the credential plugins. They need "
                "the pycryptodome package; without it hashdump, lsadump and "
                "cachedump do not load.",
            )
            return

        for plugin_id in available:
            if plugin_id not in self._runners:
                self._on_plugin_clicked(plugin_id)
        self._show_status(
            f"Running {len(available)} credential plugin(s). These yield hashes "
            "and secrets, not plaintext passwords — crack the hashes offline."
        )

    # ── Extraction ────────────────────────────────────────────────────────────

    #: What each extraction runs. vol3 writes the files itself; the table each
    #: one returns is the manifest of what it wrote.
    _EXTRACTORS = {
        "process": ("windows.pslist.PsList", "Dump Process", "process executable"),
        "memory":  ("windows.memmap.Memmap", "Dump Memory", "full process memory"),
        "dlls":    ("windows.dlllist.DllList", "Dump DLLs", "loaded modules"),
    }

    def _extract(self, payload: dict):
        """Extract a process's executable, memory or modules to the case."""
        kind = payload.get("__dump__", "")
        pid = str(payload.get("__pid__", "")).strip()
        plugin_id, title, what = self._EXTRACTORS.get(kind, (None, "", ""))
        if plugin_id is None or not pid:
            return

        info = self.registry.get(plugin_id)
        if info is None:
            QMessageBox.warning(
                self, "Not Available",
                f"{plugin_id} is not in this volatility3 installation.",
            )
            return

        target = self.dumps_dir
        if not target:
            QMessageBox.information(
                self, "No Case Folder",
                "Quick Analysis has nowhere to put extracted files. Create a "
                "case first.",
            )
            return
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(self, "Extraction Failed",
                                 f"Could not create {target}:\n\n{exc}")
            return

        if kind == "memory":
            answer = QMessageBox.question(
                self, "Dump Process Memory",
                f"Writing the full memory of PID {pid} can produce a file as "
                "large as the process's address space — often gigabytes.\n\n"
                f"It will be written to:\n{target}\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        run_key = f"{plugin_id}#dump{pid}"
        if run_key in self._runners:
            self._show_status(f"Already extracting from PID {pid}.")
            return

        panel = ResultPanel(f"{title} {pid}", plugin_id)
        panel.cancel_requested.connect(lambda key=run_key: self._cancel_run(key))
        self._wire_panel(panel)
        panel.append_log(f"Extracting {what} for PID {pid} into {target}")
        if payload.get("__lsass__"):
            panel.append_log(
                "This is the lsass process memory. volatility3 does not recover "
                "plaintext passwords itself; run the written file through "
                "pypykatz (`pypykatz lsa minidump <file>`) or an equivalent to "
                "pull credentials out of it. For registry-derived hashes, use "
                "the Credentials plugins (Password Hashes, LSA Secrets, Cached "
                "Domain) instead."
            )
        index = self.tabs.add_result_tab(panel, f"{title} {pid}")
        self.tabs.setCurrentIndex(index)
        self._panels[run_key] = panel
        panel.set_running(True)

        spec = RunSpec(
            image_path=self.case.image_path,
            plugin_id=plugin_id,
            symbol_dirs=self.symbol_dirs,
            cache_dir=self.vol_cache_dir,
            extra_args=["--pid", pid, "--dump"],
            output_dir=target,
        )
        # What is already there, so the files this run writes can be told from
        # the files earlier runs wrote. vol3's manifest column is named
        # differently by every plugin and says "Error outputting file" on
        # failure; the folder itself is the only reliable account.
        self._extract_context[run_key] = {
            "before": _listing(target),
            "kind": kind,
            "pid": pid,
            "process": _row_label(payload),
            "plugin": plugin_id,
            "dir": target,
        }

        self._start_runner(run_key, spec, panel)
        if self.db is not None:
            self.db.log_action("extract", f"{what} PID {pid} -> {target}",
                               self.case.examiner_name)
        self._show_status(f"Extracting {what} for PID {pid}…")

    def _generate_report(self):
        """
        Write the report folder: the HTML report with insights and the incident
        timeline, every result as CSV, the dumps, and a SHA-256 manifest.
        """
        if self.db is None:
            QMessageBox.information(
                self, "No Case",
                "Quick Analysis keeps no record, so there is nothing to report on. "
                "Create a case to generate a report.",
            )
            return
        from ui.report_dialog import ReportDialog
        dialog = ReportDialog(self.case, self.db, self.settings, parent=self)
        dialog.generated.connect(self._on_report_generated)
        dialog.exec()

    def _on_report_generated(self, result):
        if self.db is not None:
            self.db.log_action("report_generated", result.path, self.case.examiner_name)
        self._refresh_case_tree()
        self.notifier.notify(
            "Report generated",
            f"{result.insights} insight(s), {result.events:,} timeline events, "
            f"{result.dumps_linked + result.dumps_copied} dump(s).",
            "success",
        )

    # ── Timeline and insights ─────────────────────────────────────────────────

    def _analysis_payloads(self) -> list[dict]:
        """
        The output the timeline and insights are built from: the newest stored
        run of each plugin for the active image or, in Quick Analysis, whatever
        finished result tabs are open.
        """
        if self.db is not None:
            try:
                return self.db.latest_payloads(self.active_source_id)
            except Exception as exc:
                log.warning("Could not read stored results: %s", exc)
                return []
        payloads = []
        seen = set()
        for panel in self._result_panels():
            run_key = getattr(panel, "run_key", "") or panel.plugin_id
            if "#dump" in run_key or run_key in self._runners or panel.plugin_id in seen:
                continue
            seen.add(panel.plugin_id)
            payloads.append(panel.result_payload())
        return payloads

    def _refresh_analysis_views(self):
        if getattr(self, "timeline_view", None) is None:
            return
        payloads = self._analysis_payloads()
        have = {p.get("plugin", "") for p in payloads}
        runnable = (lambda p: self.registry.get(p) is not None
                    or not self.registry.available)
        timeline_missing = [p for p in timeline_missing_inputs(have) if runnable(p)]
        insight_missing = [p for p in insight_missing_inputs(have) if runnable(p)]
        try:
            self.timeline_view.set_payloads(payloads, timeline_missing)
            self.insights_view.set_payloads(payloads, insight_missing)
        except Exception as exc:              # analysis must never take the window down
            log.exception("Could not rebuild the timeline/insights: %s", exc)
            return
        high = sum(1 for f in self.insights_view.findings if f.severity == "high")
        index = self.tabs.indexOf(self.insights_view)
        if index >= 0:
            self.tabs.setTabText(index, f"Insights ({high})" if high else "Insights")

    def _collect(self, plugins: list[str]):
        """Run each listed plugin that is not running already; they queue on the gate."""
        image_path = self.case.image_path
        if not image_path or not os.path.exists(image_path):
            QMessageBox.warning(self, "No Image Loaded",
                                "Load a memory image first (File → Open Image).")
            return
        current = self.tabs.currentWidget()
        started = []
        for plugin_id in plugins:
            info = self.registry.get(plugin_id)
            if info is None or plugin_id in self._runners or info.needs_input:
                continue
            self._launch(info, self._default_args_for(info))
            started.append(info.short_name)
        if current is not None:
            self.tabs.setCurrentWidget(current)
        if started:
            self._show_status(
                f"Collecting: {', '.join(started)} — they run one at a time; this "
                "view updates as each finishes.")
        else:
            self._show_status("Nothing to collect — those plugins have already run.")

    def _show_plugin_output(self, plugin: str):
        """Bring up the output an event or finding came from."""
        if not plugin:
            return
        panel = self._panel_for(plugin)
        if panel is not None:
            self.tabs.setCurrentWidget(panel)
            return
        if self.db is not None:
            for result in self.db.get_results(plugin=plugin, source_id=self.active_source_id):
                self._open_stored_result(result["id"])
                return

    def _bookmark_insight(self, finding):
        if self.db is None:
            self._show_status("Quick Analysis cannot keep bookmarks.")
            return
        tag = "Suspicious" if finding.severity in ("high", "medium") else "Notable"
        self.db.save_bookmark(
            finding.title, finding.detail, finding.plugin, tag=tag,
            notes=f"Insight ({finding.severity}): {finding.category}",
            source_id=self.active_source_id,
            row={"PID": finding.pid, "Process": finding.process,
                 **{k: v for k, v in finding.evidence}},
        )
        self._refresh_case_tree()
        self._show_status(f"Bookmarked: {finding.title}")

    def _latest_report(self) -> str:
        """The most recently written report in the case, if there is one."""
        folder = self.case.reports_dir if self.case.directory else ""
        if not folder or not os.path.isdir(folder):
            return ""
        reports = [
            os.path.join(folder, name) for name in os.listdir(folder)
            if name.lower().endswith((".html", ".json"))
        ]
        return max(reports, key=os.path.getmtime, default="")

    def _close_case(self):
        """Return to the case manager without leaving the application."""
        if self._runners:
            answer = QMessageBox.question(
                self, "Analysis Running",
                f"{len(self._runners)} plugin(s) are still running. Stop them "
                "and close the case?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._reopen_manager = True
        self.close()

    def _open_symbol_manager(self):
        from ui.symbol_dialog import SymbolDialog
        base = self.case.directory or os.path.expanduser("~")
        SymbolDialog(base, parent=self, image_path=self.case.image_path,
                     case_mode=not self.case.quick_mode).exec()

    def _refresh_registry(self):
        self.registry = PluginRegistry.load(refresh=True)
        self.ribbon.reload(self.registry)
        self._refresh_image_facts()
        self._show_status(
            f"Plugin list refreshed — volatility3 {self.registry.vol_version}, "
            f"{len(self.registry.all())} plugins."
        )

    def _show_about(self):
        QMessageBox.about(
            self, "About DumpScope",
            "<b>DumpScope</b><br>Memory forensics on volatility3.<br><br>"
            f"volatility3: {self.registry.vol_version}<br>"
            f"Plugins available: {len(self.registry.all())}",
        )

    def _close_tab(self, index: int):
        widget = self.tabs.widget(index)
        if not isinstance(widget, ResultPanel):
            return
        if self.tabs.is_pinned(widget):
            self._show_status("This tab is pinned — unpin it first to close it.")
            return
        plugin_id = getattr(widget, "run_key", "") or widget.plugin_id
        if plugin_id in self._runners:
            answer = QMessageBox.question(
                self, "Stop Analysis?",
                f"{widget.plugin_name} is still running. Stop it and close the tab?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            self._cancel_run(plugin_id)
        self._panels.pop(plugin_id, None)
        self.tabs.removeTab(index)
        widget.deleteLater()

    def _show_status(self, message: str):
        self.status_bar.showMessage(f"  {message}")

    # ── Theme ─────────────────────────────────────────────────────────────────

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

    def apply_theme(self):
        QApplication.instance().setStyleSheet(build_theme(dark=self.is_dark))
        # Tiles and badges are styled by property, so the new sheet reaches them
        # without any per-widget work — but Qt needs telling to re-evaluate the
        # property-driven rules.
        icons.clear_cache()
        self._update_os_badge()
        self.ribbon.set_dark(self.is_dark)
        if getattr(self, "notifier", None) is not None:
            self.notifier.set_dark(self.is_dark)
        self.ribbon.repaint_glyphs()
        self.tabs.apply_theme(self.is_dark)
        if getattr(self, "timeline_view", None) is not None:
            self.timeline_view.set_dark(self.is_dark)
            self.insights_view.set_dark(self.is_dark)
        if getattr(self, "case_tree", None) is not None:
            self.case_tree.apply_theme(self.is_dark)
            self._refresh_case_tree()
        # Item views paint some colours with a brush, which no stylesheet can
        # reach; those have to be handed the new palette explicitly.
        for index in range(self.tabs.count()):
            widget = self.tabs.widget(index)
            if isinstance(widget, ResultPanel):
                widget.apply_theme(self.is_dark)
        self.case.is_dark = self.is_dark
        self.case.save()

    def _record_extraction(self, run_key: str) -> list[str]:
        """
        Register the files an extraction wrote, and hash them.

        Returns the new paths. Hashing runs in the background: a full process
        memory dump can be gigabytes, and hashing one on the GUI thread would
        freeze the window for as long as it took.
        """
        context = self._extract_context.pop(run_key, None)
        if context is None:
            return []
        target = context["dir"]
        written = sorted(_listing(target) - context["before"])
        paths = [os.path.join(target, name) for name in written]
        if not paths or self.db is None:
            return paths

        for path in paths:
            try:
                self.db.record_extraction(
                    path, plugin=context["plugin"], kind=context["kind"],
                    pid=context["pid"], process=context["process"],
                    source_id=self.active_source_id,
                )
            except Exception as exc:
                log.warning("Could not record %s: %s", path, exc)

        hasher = FileHasher(paths, parent=self)
        hasher.hashed.connect(self._on_extraction_hashed)
        hasher.all_done.connect(
            lambda count: self._show_status(f"Hashed {count} extracted file(s).")
        )
        hasher.finished.connect(lambda h=hasher: self._hashers.remove(h)
                                if h in self._hashers else None)
        hasher.finished.connect(hasher.deleteLater)
        self._hashers.append(hasher)
        hasher.start()
        self._refresh_case_tree()
        return paths

    def _on_extraction_hashed(self, path: str, sha256: str, _size: int):
        if self.db is not None:
            self.db.set_extraction_hash(path, sha256)

    # ── Fonts ─────────────────────────────────────────────────────────────────

    def _choose_ui_font(self):
        """
        Pick the interface font. The size chosen scales the whole sheet.

        Every size in the stylesheet is written against one base, so a choice
        of 15pt moves headings, labels and table text together instead of
        leaving a 15pt body under an 11pt heading.
        """
        current = theme_fonts()
        seed = QFont(current["ui_font"] or self.font().family(), current["size"])
        chosen, accepted = QFontDialog.getFont(seed, self, "Interface Font")
        if not accepted:
            return
        self._save_fonts(ui_font=chosen.family(),
                         font_size=chosen.pointSize() or current["size"])
        self.notifier.notify(
            "Interface font changed",
            f"{chosen.family()} at {chosen.pointSize()}pt", "info",
        )

    def _choose_mono_font(self):
        """Pick the fixed-width font used for offsets, hex and the log."""
        current = theme_fonts()
        seed = QFont(current["mono_font"] or "JetBrains Mono", current["size"])
        seed.setStyleHint(QFont.StyleHint.Monospace)
        chosen, accepted = QFontDialog.getFont(seed, self, "Monospace Font")
        if not accepted:
            return
        self._save_fonts(mono_font=chosen.family())
        self.notifier.notify("Monospace font changed", chosen.family(), "info")

    def _reset_fonts(self):
        self._save_fonts(ui_font="", mono_font="", font_size=BASE_FONT_SIZE)
        self._show_status("Fonts reset to the defaults.")

    def _save_fonts(self, **changes):
        self.settings = settings.save(**changes)
        set_fonts(self.settings.get("ui_font", ""),
                  self.settings.get("mono_font", ""),
                  int(self.settings.get("font_size") or BASE_FONT_SIZE))
        self.apply_theme()

    def _toggle_report_output(self):
        enabled = not self.settings.get("report_include_output", True)
        self.settings = settings.save(report_include_output=enabled)
        self._show_status(
            "Reports will include the analysis output." if enabled else
            "Reports will list the runs only, without their rows."
        )

    def _set_parallel_runs(self, count: int):
        self.settings = settings.save(max_parallel_runs=int(count))
        RUN_GATE.set_limit(count)
        self._show_status(
            "volatility3 runs will queue and run one at a time." if count == 1 else
            f"Up to {count} volatility3 runs may now run at once."
        )

    def _set_desktop_notifications(self, enabled: bool):
        self.settings = settings.save(desktop_notifications=bool(enabled))
        self.notifier.set_desktop_enabled(bool(enabled))
        self._show_status(
            "Desktop notifications on." if enabled else
            "Desktop notifications off — messages still appear in the window."
        )

    # ── Command palette ───────────────────────────────────────────────────────

    def open_command_palette(self):
        """Everything the window can do, searchable, over the keyboard."""
        from ui.command_palette import CommandPalette

        dialog = CommandPalette(self._commands(), parent=self, is_dark=self.is_dark)
        dialog.exec()

    def _commands(self) -> list:
        """
        The palette's contents: the window's own verbs first, then every plugin
        that can be run against the current image.

        Built fresh on each open rather than cached, because most of it depends
        on state — which OS the ribbon is scoped to, whether an image is
        loaded, which tags exist.
        """
        from ui.command_palette import Command

        commands: list[Command] = [
            Command("Open Image…", self._open_image_dialog, group="File",
                    shortcut="Ctrl+O", glyph="disk", keywords="load memory dump"),
            Command("Show Insights", lambda: self.tabs.setCurrentWidget(self.insights_view),
                    group="Analysis", glyph="shield",
                    keywords="triage findings suspicious anomalies hidden injected"),
            Command("Show Timeline", lambda: self.tabs.setCurrentWidget(self.timeline_view),
                    group="Analysis", glyph="clock",
                    keywords="incident timeline events chronology histogram"),
            Command("Collect Timeline and Insight Data",
                    lambda: self._collect(list(dict.fromkeys(
                        self.timeline_view.missing + self.insights_view.missing))),
                    group="Analysis", glyph="activity",
                    keywords="run pslist dlllist netscan malfind cmdline svcscan"),
            Command("Export Current Results…", self._export_current, group="File",
                    shortcut="Ctrl+E", glyph="download", keywords="csv json save"),
            Command("Generate Case Report…", self._generate_report, group="File",
                    shortcut="Ctrl+R", glyph="news"),
            Command("Open Case Folder", self._reveal_case_folder, group="File",
                    glyph="box"),
            Command("Include Analysis Output in Reports",
                    lambda: self._toggle_report_output(), group="File",
                    glyph="list", keywords="rows tables full detail"),
            Command("Close Case", self._close_case, group="File",
                    shortcut="Ctrl+W", glyph="lock"),
            Command("Toggle Light / Dark Theme", self.toggle_theme, group="View",
                    shortcut="Ctrl+T", glyph="sun" if self.is_dark else "moon"),
            Command("Search Plugins", self.ribbon.focus_search, group="View",
                    shortcut="Ctrl+P", glyph="search"),
            Command("Large Plugin Tiles", lambda: self.ribbon.set_compact(False),
                    group="View", glyph="layers", keywords="density comfortable big"),
            Command("Compact Plugin Tiles", lambda: self.ribbon.set_compact(True),
                    group="View", glyph="layers", keywords="density small dense"),
            Command("Go to Case Tab", lambda: self.tabs.setCurrentIndex(0),
                    group="View", glyph="badge", keywords="details examiner notes"),
            Command("Re-identify Image", self._start_os_probe, group="Image",
                    glyph="target", keywords="detect os profile probe"),
            Command("Compute Hashes", self._hash_active_source, group="Image",
                    glyph="key", keywords="md5 sha256 integrity"),
            Command("Extract Credentials (hashes, LSA, cached)",
                    self._sweep_credentials, group="Tools", glyph="unlock",
                    keywords="password lsass hashdump lsadump cachedump ntlm sam"),
            Command("Symbols & YARA…", self._open_symbol_manager, group="Tools",
                    glyph="braces", keywords="isf pdb rules download"),
            Command("Refresh Plugin List", self._refresh_registry, group="Tools",
                    glyph="shuffle", keywords="reload volatility introspect"),
            Command("New Tag…", self._new_tag, group="Tags", glyph="tag"),
            Command("Interface Font…", self._choose_ui_font, group="View",
                    glyph="news", keywords="typeface family size scale bigger"),
            Command("Monospace Font…", self._choose_mono_font, group="View",
                    glyph="terminal", keywords="fixed width hex offsets code"),
            Command("Reset Fonts", self._reset_fonts, group="View", glyph="news"),
            Command("Toggle Desktop Notifications",
                    lambda: self.notify_action.toggle(), group="View",
                    glyph="signal", keywords="alerts toast tray popup"),
        ]
        for os_name, (glyph, label) in OS_BADGES.items():
            commands.append(Command(
                f"Show {label} Plugins", lambda name=os_name: self.set_os(name, manual=True),
                group="View", glyph=glyph, keywords="operating system scope",
            ))

        # Plugins last so a bare query still surfaces the window's own verbs
        # first; the ranking puts an exact plugin name above them anyway.
        for info in self.registry.for_os(self.current_os or DEFAULT_OS):
            commands.append(Command(
                info.short_name,
                lambda plugin_id=info.id: self._on_plugin_clicked(plugin_id),
                subtitle=info.description or info.id,
                group="Run",
                glyph=icons.for_emoji(getattr(info, "icon", "")),
                keywords=f"{info.id} {info.category}",
            ))
        return commands

    def _reveal_case_folder(self):
        if not self.case.directory:
            self._show_status("Quick Analysis has no case folder.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.case.directory))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Toasts are children positioned by hand, so they have to be moved back
        # into the corner when the corner moves.
        if getattr(self, "notifier", None) is not None:
            self.notifier.handle_resize()

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def closeEvent(self, event):
        if getattr(self, "notifier", None) is not None:
            self.notifier.shutdown()
        if self._os_probe is not None:
            self._os_probe.cancel()
            self._os_probe.wait(2000)
        for runner in list(self._runners.values()):
            runner.cancel()
        for runner in list(self._runners.values()):
            if not runner.wait(3000):
                log.warning("A volatility3 run did not stop in time")
        self._runners.clear()
        super().closeEvent(event)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _listing(directory: str) -> set[str]:
    """The file names directly inside `directory`. Empty if it cannot be read."""
    try:
        with os.scandir(directory) as entries:
            return {entry.name for entry in entries if entry.is_file()}
    except OSError:
        return set()


def _row_label(row: dict) -> str:
    """
    A short human label for an output row.

    The first column of most vol3 output is a PID or an offset, which says
    nothing on its own in a tag list; a name is what an examiner recognises.
    """
    for key in ("ImageFileName", "Process", "Name", "BaseDllName", "Key",
                "Path", "FullDllPath", "Value", "File output"):
        value = str(row.get(key) or "").strip()
        if value and value not in ("N/A", "-"):
            return value if len(value) <= 60 else "…" + value[-59:]
    for value in row.values():
        text = str(value or "").strip()
        if text:
            return text[:60]
    return ""


def _format_size(path: str) -> str:
    if not path or not os.path.exists(path):
        return "—"
    try:
        size = float(os.path.getsize(path))
    except OSError:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"
