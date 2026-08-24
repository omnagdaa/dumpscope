"""
The analysis window: plugin ribbon, result tabs, and the case overview.
"""

from __future__ import annotations

import logging
import os

from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import (
    QApplication, QDockWidget, QFileDialog, QFrame, QGridLayout, QGroupBox,
    QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QScrollArea, QStatusBar, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget,
)

from core.case import Case, remember_case
from core.database import Database
from core.plugins import PluginRegistry, build_command_args
from core.vol_runner import OsProbe, RunSpec, VolatilityRunner
from core.hash_worker import HashWorker
from core.report import write_report
from ui.bookmark_dialog import BookmarkDialog
from ui.case_tree import CaseTree
from ui.plugin_args_dialog import PluginArgsDialog
from ui.plugin_button import PluginButton
from ui.result_panel import ResultPanel
from ui.theme import DARK_THEME, LIGHT_THEME

log = logging.getLogger("dumpscope.main_window")

OS_BADGES = {
    "windows": ("🪟", "Windows", "#1f3d5c", "#58a6ff"),
    "linux":   ("🐧", "Linux",   "#1a3d1a", "#3fb950"),
    "mac":     ("🍎", "macOS",   "#3d2a1a", "#f0883e"),
}

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
        self.current_os = "windows"

        self._runners: dict[str, VolatilityRunner] = {}
        self._panels: dict[str, ResultPanel] = {}
        self._plugin_buttons: dict[str, PluginButton] = {}
        self._os_probe: OsProbe | None = None
        self.active_source_id: int | None = None

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
        if not base:
            return
        for sub in ("symbols", "yara", "exports", "dumps"):
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
    def symbol_dirs(self) -> list[str]:
        base = self.case.directory
        return [os.path.join(base, "symbols")] if base else []

    # ── Construction ──────────────────────────────────────────────────────────

    def _build(self):
        self._build_menu()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_topbar())

        self.ribbon_host = QWidget()
        self.ribbon_host_layout = QVBoxLayout(self.ribbon_host)
        self.ribbon_host_layout.setContentsMargins(0, 0, 0, 0)
        self.ribbon = self._build_ribbon(self.current_os)
        self.ribbon_host_layout.addWidget(self.ribbon)
        root.addWidget(self.ribbon_host)

        self._build_case_dock()

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.tabBar().setTabButton(0, self.tabs.tabBar().ButtonPosition.RightSide, None)
        root.addWidget(self.tabs, 1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def _build_case_dock(self):
        """
        The case explorer, docked left. Quick Analysis has no case to explore,
        so it is not created at all rather than shown empty.
        """
        if self.db is None:
            self.case_tree = None
            return

        self.case_tree = CaseTree()
        self.case_tree.source_activated.connect(self._activate_source)
        self.case_tree.source_remove.connect(self._remove_source)
        self.case_tree.source_hash.connect(self._hash_source)
        self.case_tree.add_source.connect(self._open_image_dialog)
        self.case_tree.result_opened.connect(self._open_stored_result)
        self.case_tree.result_deleted.connect(self._delete_stored_result)
        self.case_tree.bookmark_activated.connect(self._show_bookmark)
        self.case_tree.bookmark_deleted.connect(self._delete_bookmark)

        dock = QDockWidget("Case", self)
        dock.setObjectName("caseDock")
        dock.setWidget(self.case_tree)
        dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )
        self.case_dock = dock
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)
        dock.setMinimumWidth(240)
        self._refresh_case_tree()

    def _refresh_case_tree(self):
        if getattr(self, "case_tree", None) is None or self.db is None:
            return
        try:
            self.case_tree.refresh(
                self.db.get_data_sources(),
                self.db.get_results(),
                self.db.get_bookmarks(),
                active_source_id=self.active_source_id,
            )
        except Exception as exc:
            log.warning("Could not refresh the case tree: %s", exc)

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
        self._refresh_case_tree()
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
        self._refresh_case_tree()
        self._show_status(f"Hashed — MD5 {md5[:16]}…")

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
        panel.bookmark_requested.connect(self._save_bookmark)
        panel.set_columns(stored["columns"])
        panel.append_rows(stored["rows"])
        panel.set_finished(0)
        panel.append_log(f"Stored result from {stored.get('created_at', 'an earlier run')}.")

        index = self.tabs.addTab(panel, f"{short} (saved)")
        self.tabs.setCurrentIndex(index)
        self._show_status(f"Opened stored {short} — {len(stored['rows']):,} rows.")

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

        view_menu = bar.addMenu("&View")
        theme_action = QAction("Toggle Theme", self)
        theme_action.setShortcut("Ctrl+T")
        theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(theme_action)

        for os_name in ("windows", "linux", "mac"):
            action = QAction(f"Show {OS_BADGES[os_name][1]} Plugins", self)
            action.triggered.connect(lambda _, name=os_name: self.set_os(name, manual=True))
            view_menu.addAction(action)

        tools_menu = bar.addMenu("&Tools")
        symbols_action = QAction("Symbols && YARA…", self)
        symbols_action.triggered.connect(self._open_symbol_manager)
        tools_menu.addAction(symbols_action)

        refresh_action = QAction("Refresh Plugin List", self)
        refresh_action.triggered.connect(self._refresh_registry)
        tools_menu.addAction(refresh_action)

        help_menu = bar.addMenu("&Help")
        about_action = QAction("About DumpScope", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("topBar")
        bar.setFixedHeight(54)
        row = QHBoxLayout(bar)
        row.setContentsMargins(20, 0, 20, 0)
        row.setSpacing(12)

        logo = QLabel("DumpScope")
        logo.setObjectName("appLogo")

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.VLine)
        separator.setFixedWidth(1)

        self.case_tag = QLabel(self.case.case_name)
        self.case_tag.setObjectName("caseTag")

        image_path = self.case.image_path
        self.image_lbl = QLabel()
        self.image_lbl.setObjectName("imageLabel")
        self._set_image_label(image_path)

        self.os_badge = QLabel()
        self.os_badge.setObjectName("osBadge")

        symbols_btn = QPushButton("Symbols & YARA")
        symbols_btn.setFixedWidth(140)
        symbols_btn.clicked.connect(self._open_symbol_manager)

        self.theme_btn = QPushButton("Light" if self.is_dark else "Dark")
        self.theme_btn.setFixedWidth(84)
        self.theme_btn.clicked.connect(self.toggle_theme)

        row.addWidget(logo)
        row.addWidget(separator)
        row.addWidget(self.case_tag)
        row.addWidget(self.image_lbl)
        row.addWidget(self.os_badge)
        row.addStretch()
        row.addWidget(symbols_btn)
        row.addWidget(self.theme_btn)

        self._update_os_badge()
        return bar

    def _build_ribbon(self, os_name: str) -> QWidget:
        outer = QWidget()
        outer.setObjectName("pluginRibbon")
        outer.setFixedHeight(152)

        scroll = QScrollArea(outer)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        row = QHBoxLayout(inner)
        row.setContentsMargins(16, 6, 16, 6)
        row.setSpacing(0)
        row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self._plugin_buttons.clear()
        groups = self.registry.ribbon(os_name)

        for index, (category, color, plugins) in enumerate(groups):
            group = QWidget()
            group.setStyleSheet("background: transparent;")
            column = QVBoxLayout(group)
            column.setContentsMargins(8, 0, 8, 0)
            column.setSpacing(4)

            heading = QLabel(category.upper())
            heading.setStyleSheet(
                f"font-size: 9px; font-weight: 800; color: {color};"
                "background: transparent; letter-spacing: 1.5px;"
            )
            heading.setFixedHeight(14)

            tiles = QWidget()
            tiles.setStyleSheet("background: transparent;")
            tile_row = QHBoxLayout(tiles)
            tile_row.setContentsMargins(0, 0, 0, 0)
            tile_row.setSpacing(6)

            for info in plugins:
                button = PluginButton(info, dark=self.is_dark)
                button.clicked.connect(self._on_plugin_clicked)
                self._plugin_buttons[info.id] = button
                tile_row.addWidget(button)

            column.addWidget(heading)
            column.addWidget(tiles)
            row.addWidget(group)

            if index < len(groups) - 1:
                divider = QFrame()
                divider.setFrameShape(QFrame.Shape.VLine)
                divider.setFixedWidth(1)
                divider.setObjectName("ribbonDivider")
                row.addWidget(divider)

        row.addStretch()
        scroll.setWidget(inner)

        layout = QVBoxLayout(outer)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)
        return outer

    def _build_overview_tab(self) -> QWidget:
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        title = QLabel(f"Case: {self.case.case_name}")
        title.setObjectName("overviewTitle")
        layout.addWidget(title)

        blurb = QLabel(
            "Use File → Open Image to load a memory dump, then choose a plugin."
            if self.case.quick_mode else
            "Select an analysis module from the ribbon above. Each plugin runs "
            "volatility3 in its own process and streams results into a tab."
        )
        blurb.setWordWrap(True)
        blurb.setObjectName("overviewBlurb")
        layout.addWidget(blurb)

        summary = QGroupBox("Case Summary")
        grid = QGridLayout(summary)
        grid.setSpacing(12)
        image_path = self.case.image_path
        grid.addWidget(_stat_card("Image Size", _format_size(image_path)), 0, 0)
        grid.addWidget(_stat_card("Case Number",
                                  self.case.case_number or "—"), 0, 1)
        grid.addWidget(_stat_card("Examiner",
                                  self.case.examiner_name or "—"), 0, 2)
        grid.addWidget(_stat_card("Plugins Available",
                                  str(len(self.registry.for_os(self.current_os)))), 0, 3)
        layout.addWidget(summary)

        integrity = QGroupBox("Image Integrity")
        integrity_grid = QGridLayout(integrity)
        integrity_grid.setSpacing(10)
        integrity_grid.setColumnStretch(1, 1)
        for row_index, (label, key) in enumerate((("MD5", "md5"), ("SHA-256", "sha256"))):
            name = QLabel(label)
            name.setFixedWidth(70)
            value = QLineEdit(getattr(self.case, key, "") or "—")
            value.setReadOnly(True)
            integrity_grid.addWidget(name, row_index, 0)
            integrity_grid.addWidget(value, row_index, 1)
        layout.addWidget(integrity)

        if self.case.notes:
            notes_group = QGroupBox("Case Notes")
            notes_layout = QVBoxLayout(notes_group)
            notes = QTextEdit(self.case.notes)
            notes.setReadOnly(True)
            notes.setMaximumHeight(110)
            notes_layout.addWidget(notes)
            layout.addWidget(notes_group)

        layout.addStretch()
        area.setWidget(inner)
        return area

    # ── OS handling ───────────────────────────────────────────────────────────

    def _start_os_probe(self):
        image_path = self.case.image_path
        if not image_path or not os.path.exists(image_path):
            return
        self._show_status("Identifying image operating system…")
        probe = OsProbe(image_path, self.symbol_dirs, parent=self)
        probe.detected.connect(lambda name: self.set_os(name))
        probe.undetermined.connect(self._on_os_undetermined)
        probe.finished.connect(lambda: setattr(self, "_os_probe", None))
        self._os_probe = probe
        probe.start()

    def _on_os_undetermined(self, reason: str):
        log.info("OS probe inconclusive: %s", reason)
        self._show_status(
            f"Could not identify the image OS ({reason}) — showing "
            f"{OS_BADGES[self.current_os][1]} plugins. Change it under View."
        )

    def set_os(self, os_name: str, manual: bool = False):
        if os_name not in OS_BADGES or os_name == self.current_os:
            return
        self.current_os = os_name
        old = self.ribbon
        self.ribbon = self._build_ribbon(os_name)
        self.ribbon_host_layout.replaceWidget(old, self.ribbon)
        old.deleteLater()
        self._update_os_badge()
        self.apply_theme()
        if self.db and self.active_source_id and not manual:
            try:
                self.db.add_data_source(self.case.image_path, os_hint=os_name)
                self._refresh_case_tree()
            except Exception as exc:
                log.debug("Could not record the detected OS: %s", exc)
        label = OS_BADGES[os_name][1]
        self._show_status(
            f"Showing {label} plugins."
            if manual else f"Detected {label} image — plugin ribbon updated."
        )

    def _update_os_badge(self):
        icon, label, background, foreground = OS_BADGES[self.current_os]
        self.os_badge.setText(f"{icon}  {label}")
        self.os_badge.setStyleSheet(
            f"background-color: {background}; color: {foreground};"
            "border-radius: 4px; padding: 3px 10px; font-size: 11px; font-weight: 700;"
        )

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
        panel.cancel_requested.connect(lambda pid=info.id: self._cancel_run(pid))
        panel.bookmark_requested.connect(self._save_bookmark)

        index = self.tabs.addTab(panel, info.short_name)
        self.tabs.setCurrentIndex(index)
        self._panels[info.id] = panel
        panel.set_running(True)

        button = self._plugin_buttons.get(info.id)
        if button:
            button.set_running(True)

        spec = RunSpec(
            image_path=self.case.image_path,
            plugin_id=info.id,
            symbol_dirs=self.symbol_dirs,
            extra_args=extra_args,
        )
        runner = VolatilityRunner(spec, parent=self)
        runner.columns_ready.connect(panel.set_columns)
        runner.rows_ready.connect(panel.append_rows)
        runner.progress.connect(panel.set_progress)
        runner.log_line.connect(panel.append_log)
        runner.failed.connect(panel.set_error)
        runner.run_finished.connect(
            lambda code, pid=info.id: self._on_run_finished(code, pid)
        )
        self._runners[info.id] = runner
        runner.start()

        log.info("Started %s %s", info.id, " ".join(extra_args))
        self._show_status(f"Running {info.short_name}…")

    def _cancel_run(self, plugin_id: str):
        runner = self._runners.get(plugin_id)
        if runner:
            runner.cancel()
            self._show_status(f"Stopping {plugin_id}…")

    def _on_run_finished(self, exit_code: int, plugin_id: str):
        runner = self._runners.pop(plugin_id, None)
        panel = self._panels.get(plugin_id)
        cancelled = bool(runner and runner.cancelled)

        if panel:
            panel.set_finished(exit_code, cancelled=cancelled)
            if self.db and exit_code == 0 and not cancelled:
                try:
                    self.db.save_analysis(plugin_id, panel.result_payload(),
                                          source_id=self.active_source_id)
                except Exception as exc:
                    log.warning("Could not store results for %s: %s", plugin_id, exc)

        button = self._plugin_buttons.get(plugin_id)
        if button:
            button.set_running(False)

        if runner:
            runner.wait(3000)
        self._refresh_case_tree()

        rows = panel.model.rowCount() if panel else 0
        short = plugin_id.rsplit(".", 1)[-1]
        if cancelled:
            self._show_status(f"{short} cancelled.")
        elif exit_code == 0:
            self._show_status(f"{short} finished — {rows:,} rows.")
        else:
            self._show_status(f"{short} failed (exit {exit_code}). See the Log tab.")

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
        self._show_status(f"Loaded {os.path.basename(path)}")
        self._start_os_probe()

    def _set_image_label(self, path: str):
        if path:
            self.image_lbl.setText(os.path.basename(path))
            self.image_lbl.setToolTip(path)
        else:
            self.image_lbl.setText("No image loaded")
            self.image_lbl.setToolTip("")

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

    def _generate_report(self):
        """Write an HTML or JSON case report into the case's reports folder."""
        if self.db is None:
            QMessageBox.information(
                self, "No Case",
                "Quick Analysis keeps no record, so there is nothing to report on.",
            )
            return

        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        default = os.path.join(
            self.case.reports_dir,
            f"{self.case.case_name.replace(' ', '_')}-{stamp}.html",
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Generate Case Report", default,
            "HTML Report (*.html);;JSON Report (*.json)",
        )
        if not path:
            return

        fmt = "json" if path.lower().endswith(".json") else "html"
        try:
            write_report(
                path, self.case,
                self.db.get_data_sources(), self.db.get_results(),
                self.db.get_bookmarks(), self.db.get_audit_log(), fmt=fmt,
            )
            self.db.log_action("report_generated", path, self.case.examiner_name)
        except OSError as exc:
            QMessageBox.critical(self, "Report Failed", str(exc))
            return

        self._refresh_case_tree()
        answer = QMessageBox.question(
            self, "Report Generated",
            f"Written to:\n{path}\n\nOpen it now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

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
        SymbolDialog(base, parent=self).exec()

    def _refresh_registry(self):
        self.registry = PluginRegistry.load(refresh=True)
        current = self.current_os
        self.current_os = ""            # force the rebuild in set_os
        self.set_os(current, manual=True)
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
        plugin_id = widget.plugin_id
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
        QApplication.instance().setStyleSheet(DARK_THEME if self.is_dark else LIGHT_THEME)
        self.theme_btn.setText("Light" if self.is_dark else "Dark")
        for button in self._plugin_buttons.values():
            button.set_dark(self.is_dark)
        self._update_os_badge()

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def closeEvent(self, event):
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

def _stat_card(title: str, value: str) -> QWidget:
    card = QWidget()
    card.setObjectName("statCard")
    layout = QVBoxLayout(card)
    layout.setSpacing(4)
    value_lbl = QLabel(value)
    value_lbl.setObjectName("statValue")
    title_lbl = QLabel(title)
    title_lbl.setObjectName("statTitle")
    layout.addWidget(value_lbl)
    layout.addWidget(title_lbl)
    return card


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
