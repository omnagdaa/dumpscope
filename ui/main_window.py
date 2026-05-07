import os
import sys
import logging
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTabWidget, QTextEdit, QStatusBar,
    QApplication, QGroupBox, QGridLayout, QLineEdit,
    QScrollArea, QFrame, QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from ui.theme import DARK_THEME, LIGHT_THEME
from ui.plugin_button import PluginButton
from ui.result_panel import ResultPanel
from core.database import Database
from core.vol_worker import VolatilityWorker

log = logging.getLogger("dumpscope.main_window")

# ── Plugin registry ───────────────────────────────────────────────────────────
PLUGINS_WINDOWS = [
    # Processes
    {"id": "windows.pslist.PsList",         "name": "Process\nList",      "icon": "🗂",  "color": "#58a6ff"},
    {"id": "windows.pstree.PsTree",         "name": "Process\nTree",      "icon": "🌲",  "color": "#58a6ff"},
    {"id": "windows.cmdline.CmdLine",       "name": "CmdLine",            "icon": "💬",  "color": "#58a6ff"},
    {"id": "windows.dlllist.DllList",       "name": "DLL\nList",          "icon": "📦",  "color": "#58a6ff"},
    {"id": "windows.handles.Handles",       "name": "Handles",            "icon": "🔗",  "color": "#58a6ff"},
    {"id": "windows.malfind.Malfind",       "name": "Malfind",            "icon": "🦠",  "color": "#f85149"},
    # Network
    {"id": "windows.netstat.NetStat",       "name": "NetStat",            "icon": "🌐",  "color": "#3fb950"},
    {"id": "windows.netscan.NetScan",       "name": "NetScan",            "icon": "📡",  "color": "#3fb950"},
    # Memory
    {"id": "windows.memmap.Memmap",         "name": "Mem\nMap",           "icon": "🗺",  "color": "#f0883e"},
    {"id": "windows.vadinfo.VadInfo",       "name": "VAD\nInfo",          "icon": "🧩",  "color": "#f0883e"},
    {"id": "windows.dumpfiles.DumpFiles",   "name": "Dump\nFiles",        "icon": "💾",  "color": "#f0883e"},
    {"id": "windows.strings.Strings",       "name": "Strings",            "icon": "🔤",  "color": "#f0883e"},
    # Registry
    {"id": "windows.registry.hivelist.HiveList",     "name": "Hive\nList",  "icon": "📋", "color": "#bc8cff"},
    {"id": "windows.registry.printkey.PrintKey",     "name": "Print\nKey",  "icon": "🔑", "color": "#bc8cff"},
    {"id": "windows.registry.userassist.UserAssist", "name": "User\nAssist","icon": "👤", "color": "#bc8cff"},
    # System
    {"id": "windows.info.Info",             "name": "Sys\nInfo",          "icon": "ℹ",  "color": "#e3b341"},
    {"id": "windows.modules.Modules",       "name": "Modules",            "icon": "⚙",  "color": "#e3b341"},
    {"id": "windows.driverscan.DriverScan", "name": "Driver\nScan",       "icon": "🚗",  "color": "#e3b341"},
    {"id": "windows.ssdt.SSDT",             "name": "SSDT",               "icon": "🛡",  "color": "#e3b341"},
    {"id": "windows.filescan.FileScan",     "name": "File\nScan",         "icon": "🔍",  "color": "#e3b341"},
    # Hunt
    {"id": "windows.yarascan.YaraScan",     "name": "Yara\nScan",         "icon": "🎯",  "color": "#f85149"},
]

PLUGINS_LINUX = [
    # Processes
    {"id": "linux.pslist.PsList",           "name": "Process\nList",      "icon": "🗂",  "color": "#58a6ff"},
    {"id": "linux.pstree.PsTree",           "name": "Process\nTree",      "icon": "🌲",  "color": "#58a6ff"},
    {"id": "linux.bash.Bash",               "name": "Bash\nHistory",      "icon": "💬",  "color": "#58a6ff"},
    {"id": "linux.elfs.Elfs",               "name": "ELF\nFiles",         "icon": "📦",  "color": "#58a6ff"},
    {"id": "linux.lsof.Lsof",              "name": "Open\nFiles",         "icon": "🔗",  "color": "#58a6ff"},
    {"id": "linux.malfind.Malfind",         "name": "Malfind",            "icon": "🦠",  "color": "#f85149"},
    # Network
    {"id": "linux.netfilter.Netfilter",     "name": "Netfilter",          "icon": "🌐",  "color": "#3fb950"},
    {"id": "linux.sockstat.Sockstat",       "name": "Sockstat",           "icon": "📡",  "color": "#3fb950"},
    # Memory
    {"id": "linux.memmap.Memmap",           "name": "Mem\nMap",           "icon": "🗺",  "color": "#f0883e"},
    {"id": "linux.proc.Maps",               "name": "Proc\nMaps",         "icon": "🧩",  "color": "#f0883e"},
    {"id": "linux.strings.Strings",         "name": "Strings",            "icon": "🔤",  "color": "#f0883e"},
    # System
    {"id": "linux.lsmod.Lsmod",             "name": "Modules",            "icon": "⚙",  "color": "#e3b341"},
    {"id": "linux.check_syscall.Check_syscall", "name": "Syscall\nCheck", "icon": "🛡",  "color": "#e3b341"},
    {"id": "linux.keyboard_notifiers.Keyboard_notifiers", "name": "Keyboard\nNotifiers", "icon": "⌨",  "color": "#e3b341"},
    {"id": "linux.filescan.FileScan",       "name": "File\nScan",         "icon": "🔍",  "color": "#e3b341"},
    # Hunt
    {"id": "linux.yarascan.YaraScan",       "name": "Yara\nScan",         "icon": "🎯",  "color": "#f85149"},
]

CATEGORIES_WINDOWS = [
    ("Processes", "#58a6ff", 6),
    ("Network",   "#3fb950", 2),
    ("Memory",    "#f0883e", 4),
    ("Registry",  "#bc8cff", 3),
    ("System",    "#e3b341", 5),
    ("Hunt",      "#f85149", 1),
]

CATEGORIES_LINUX = [
    ("Processes", "#58a6ff", 6),
    ("Network",   "#3fb950", 2),
    ("Memory",    "#f0883e", 3),
    ("System",    "#e3b341", 5),
    ("Hunt",      "#f85149", 1),
]


class MainWindow(QMainWindow):
    def __init__(self, case_data: dict, parent=None):
        super().__init__(parent)
        self.case_data   = case_data
        self.is_dark     = case_data.get("is_dark", True)
        self._detected_os = "windows"   # updated after first plugin run
        self._workers:    dict[str, VolatilityWorker] = {}
        self._plugin_btns: dict[str, PluginButton]   = {}

        # Database — skip in quick/analysis mode
        if not case_data.get("quick_mode"):
            self.db = Database(case_data["base_dir"], case_data["case_name"])
            self.db.save_case(case_data)
        else:
            self.db = None

        for sub in ("symbols", "yara"):
            try:
                os.makedirs(os.path.join(case_data["base_dir"], sub), exist_ok=True)
            except Exception:
                pass

        self._build()
        self.apply_theme()
        title = f"DumpScope — {case_data['case_name']}"
        if not case_data.get("quick_mode"):
            title += f"  [{case_data['case_number']}]"
        self.setWindowTitle(title)
        self.resize(1360, 860)
        self._show_status("Ready. Select a plugin to begin analysis.")

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self._build_menu()
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        root.addWidget(self._build_topbar())
        self.ribbon_container = QWidget()
        self.ribbon_layout_outer = QVBoxLayout(self.ribbon_container)
        self.ribbon_layout_outer.setContentsMargins(0, 0, 0, 0)
        self._ribbon_widget = self._build_plugin_ribbon("windows")
        self.ribbon_layout_outer.addWidget(self._ribbon_widget)
        root.addWidget(self.ribbon_container)

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)
        self.tab_widget.addTab(self._build_overview_tab(), "📊  Overview")

        root.addWidget(self.tab_widget, 1)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def _build_menu(self):
        mb = self.menuBar()

        fm = mb.addMenu("File")

        open_img_act = QAction("Open Image…", self)
        open_img_act.setShortcut("Ctrl+O")
        open_img_act.triggered.connect(self._open_image_dialog)
        fm.addAction(open_img_act)

        fm.addSeparator()

        export_act = QAction("Export Report", self)
        fm.addAction(export_act)

        fm.addSeparator()

        qa = QAction("Exit", self)
        qa.setShortcut("Ctrl+Q")
        qa.triggered.connect(self.close)
        fm.addAction(qa)

        vm = mb.addMenu("View")
        ta = QAction("Toggle Theme", self)
        ta.setShortcut("Ctrl+T")
        ta.triggered.connect(self.toggle_theme)
        vm.addAction(ta)

        hm = mb.addMenu("Help")
        hm.addAction(QAction("About DumpScope", self))

    def _build_topbar(self):
        bar = QWidget()
        bar.setObjectName("topBar")
        bar.setFixedHeight(54)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(14)

        logo = QLabel("🔬 DumpScope")
        logo.setStyleSheet(
            "font-size: 19px; font-weight: 800; color: #58a6ff;"
            "background: transparent; letter-spacing: 1px;"
        )

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFixedWidth(1)

        self.case_tag = QLabel(self.case_data.get("case_name", "Quick Analysis"))
        self.case_tag.setStyleSheet(
            "background-color: #21262d; color: #8b949e; border-radius: 5px;"
            "padding: 4px 12px; font-size: 12px; font-weight: 600;"
        )

        ip = self.case_data.get("image_path", "")
        self.img_lbl = QLabel(f"🗂  {os.path.basename(ip)}" if ip else "No image loaded")
        self.img_lbl.setStyleSheet(
            "color: #3fb950; font-size: 11px; background: transparent; font-weight: 600;"
        )

        # OS badge
        self.os_badge = QLabel("🪟 Windows")
        self.os_badge.setStyleSheet(
            "background-color: #1f3d5c; color: #58a6ff; border-radius: 4px;"
            "padding: 3px 10px; font-size: 11px; font-weight: 700;"
        )

        sym_btn = QPushButton("🔣  Symbols & YARA")
        sym_btn.setFixedWidth(150)
        sym_btn.clicked.connect(self._open_symbol_manager)

        self.theme_btn = QPushButton("☀  Light" if self.is_dark else "🌙  Dark")
        self.theme_btn.setFixedWidth(100)
        self.theme_btn.clicked.connect(self.toggle_theme)

        layout.addWidget(logo)
        layout.addWidget(sep)
        layout.addWidget(self.case_tag)
        layout.addWidget(self.img_lbl)
        layout.addWidget(self.os_badge)
        layout.addStretch()
        layout.addWidget(sym_btn)
        layout.addWidget(self.theme_btn)
        return bar

    def _build_plugin_ribbon(self, os_name: str) -> QWidget:
        plugins    = PLUGINS_WINDOWS if os_name == "windows" else PLUGINS_LINUX
        categories = CATEGORIES_WINDOWS if os_name == "windows" else CATEGORIES_LINUX

        self._plugin_btns.clear()

        outer = QWidget()
        outer.setObjectName("pluginRibbon")
        outer.setFixedHeight(150)

        scroll = QScrollArea(outer)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setFixedHeight(150)

        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        h_layout = QHBoxLayout(inner)
        h_layout.setContentsMargins(16, 6, 16, 6)
        h_layout.setSpacing(0)
        h_layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        plugin_iter = iter(plugins)
        for cat_idx, (cat_name, cat_color, count) in enumerate(categories):
            cat_plugins = [next(plugin_iter) for _ in range(count)]

            grp = QWidget()
            grp.setStyleSheet("background: transparent;")
            gl = QVBoxLayout(grp)
            gl.setContentsMargins(8, 0, 8, 0)
            gl.setSpacing(4)

            cat_lbl = QLabel(cat_name.upper())
            cat_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
            cat_lbl.setStyleSheet(
                f"font-size: 9px; font-weight: 800; color: {cat_color};"
                f"background: transparent; letter-spacing: 1.5px;"
            )
            cat_lbl.setFixedHeight(14)

            btn_row = QWidget()
            btn_row.setStyleSheet("background: transparent;")
            bh = QHBoxLayout(btn_row)
            bh.setContentsMargins(0, 0, 0, 0)
            bh.setSpacing(6)

            for p in cat_plugins:
                btn = PluginButton(p["id"], p["name"], p["icon"], p["color"])
                btn.clicked.connect(self._on_plugin_clicked)
                self._plugin_btns[p["id"]] = btn
                bh.addWidget(btn)

            gl.addWidget(cat_lbl)
            gl.addWidget(btn_row)
            h_layout.addWidget(grp)

            if cat_idx < len(categories) - 1:
                vsep = QFrame()
                vsep.setFrameShape(QFrame.Shape.VLine)
                vsep.setFixedWidth(1)
                vsep.setStyleSheet("background-color: #30363d; margin: 10px 4px;")
                h_layout.addWidget(vsep)

        h_layout.addStretch()
        scroll.setWidget(inner)

        rl = QVBoxLayout(outer)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(scroll)
        return outer

    def _switch_ribbon(self, os_name: str):
        """Swap the plugin ribbon when OS is detected."""
        if self._detected_os == os_name:
            return
        self._detected_os = os_name
        log.info("Switching ribbon to OS: %s", os_name)

        old = self._ribbon_widget
        self._ribbon_widget = self._build_plugin_ribbon(os_name)
        self.ribbon_layout_outer.replaceWidget(old, self._ribbon_widget)
        old.deleteLater()

        icons = {"windows": "🪟", "linux": "🐧", "mac": "🍎"}
        names = {"windows": "Windows", "linux": "Linux", "mac": "macOS"}
        colors = {"windows": "#1f3d5c", "linux": "#1a3d1a", "mac": "#3d2a1a"}
        text_colors = {"windows": "#58a6ff", "linux": "#3fb950", "mac": "#f0883e"}

        self.os_badge.setText(f"{icons.get(os_name,'?')} {names.get(os_name,'Unknown')}")
        self.os_badge.setStyleSheet(
            f"background-color: {colors.get(os_name,'#21262d')};"
            f"color: {text_colors.get(os_name,'#e6edf3')};"
            "border-radius: 4px; padding: 3px 10px; font-size: 11px; font-weight: 700;"
        )
        self.apply_theme()
        self._show_status(f"Detected OS: {names.get(os_name, os_name)} — plugin ribbon updated.")

    # ── Overview ──────────────────────────────────────────────────────────────

    def _build_overview_tab(self):
        w = QScrollArea()
        w.setWidgetResizable(True)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        title = QLabel(f"Case: {self.case_data['case_name']}")
        title.setStyleSheet(
            "font-size: 20px; font-weight: 700; color: #58a6ff; background: transparent;"
        )
        layout.addWidget(title)

        if self.case_data.get("quick_mode"):
            hint = QLabel(
                "Quick Analysis mode — use  File → Open Image  to load a memory dump,\n"
                "then click any plugin in the ribbon above."
            )
            hint.setStyleSheet("color: #f0883e; background: transparent; font-size: 13px;")
            hint.setWordWrap(True)
            layout.addWidget(hint)
        else:
            desc = QLabel(
                "Select any analysis module from the plugin ribbon above to begin.\n"
                "Each plugin runs Volatility3 in a background thread."
            )
            desc.setWordWrap(True)
            desc.setStyleSheet("color: #8b949e; background: transparent; font-size: 13px;")
            layout.addWidget(desc)

        stats_grp = QGroupBox("Case Summary")
        sg = QGridLayout(stats_grp)
        sg.setSpacing(12)

        ip = self.case_data.get("image_path", "")
        img_size = _file_size(ip) if ip and os.path.exists(ip) else "—"

        sg.addWidget(_stat_card("Image Size",   img_size,                                    "💾"), 0, 0)
        sg.addWidget(_stat_card("Case Number",  self.case_data.get("case_number", "—"),      "📁"), 0, 1)
        sg.addWidget(_stat_card("Examiner",     self.case_data.get("examiner_name","—") or "—","👤"), 0, 2)
        sg.addWidget(_stat_card("Plugins",      str(len(PLUGINS_WINDOWS) + len(PLUGINS_LINUX)),"🔬"), 0, 3)
        layout.addWidget(stats_grp)

        hash_grp = QGroupBox("Image Integrity")
        hg = QGridLayout(hash_grp)
        hg.setSpacing(10)
        hg.setColumnStretch(1, 1)
        for row, (label, key) in enumerate([("MD5", "md5"), ("SHA-256", "sha256")]):
            l = QLabel(label)
            l.setStyleSheet("color:#8b949e;font-weight:600;background:transparent;font-size:12px;")
            l.setFixedWidth(70)
            v = QLineEdit(self.case_data.get(key, "") or "—")
            v.setReadOnly(True)
            hg.addWidget(l, row, 0)
            hg.addWidget(v, row, 1)
        layout.addWidget(hash_grp)

        if self.case_data.get("notes"):
            ng = QGroupBox("Case Notes")
            nl = QVBoxLayout(ng)
            nte = QTextEdit(self.case_data["notes"])
            nte.setReadOnly(True)
            nte.setMaximumHeight(100)
            nl.addWidget(nte)
            layout.addWidget(ng)

        layout.addStretch()
        w.setWidget(inner)
        return w

    # ── Open image (quick mode / File menu) ───────────────────────────────────

    def _open_image_dialog(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Memory Image", "",
            "Memory Images (*.raw *.mem *.vmem *.dmp *.img *.bin);;All Files (*)"
        )
        if not path:
            return
        self.case_data["image_path"] = path
        self.img_lbl.setText(f"🗂  {os.path.basename(path)}")
        log.info("Image loaded: %s", path)
        self._show_status(f"Image loaded: {os.path.basename(path)}")

    # ── Symbol manager ────────────────────────────────────────────────────────

    def _open_symbol_manager(self):
        from ui.symbol_dialog import SymbolDialog
        dlg = SymbolDialog(self.case_data["base_dir"], parent=self)
        dlg.exec()

    # ── Plugin execution ──────────────────────────────────────────────────────

    def _on_plugin_clicked(self, plugin_id: str, display_name: str):
        image_path = self.case_data.get("image_path", "")
        if not image_path:
            QMessageBox.warning(
                self, "No Image",
                "No memory image loaded.\n\nUse  File → Open Image  to select one."
            )
            return

        clean_name = display_name.replace("\n", " ").strip()

        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i).strip() == f"⚡  {clean_name}":
                self.tab_widget.setCurrentIndex(i)
                return

        panel = ResultPanel(clean_name)
        panel.set_running(True)
        tab_idx = self.tab_widget.addTab(panel, f"⚡  {clean_name}")
        self.tab_widget.setCurrentIndex(tab_idx)

        btn = self._plugin_btns.get(plugin_id)
        if btn:
            btn.set_running(True)

        panel.append_line(f"▶  Plugin : {plugin_id}")
        panel.append_line(f"   Image  : {image_path}")
        panel.append_line(
            "  ◌  Symbol tables fetched automatically on first run (requires internet)"
        )
        panel.append_line("─" * 80)

        yara_file = None
        if "yarascan" in plugin_id.lower():
            yara_dir = os.path.join(self.case_data["base_dir"], "yara")
            yara_files = [
                os.path.join(yara_dir, f)
                for f in os.listdir(yara_dir)
                if f.endswith((".yar", ".yara", ".rule"))
            ] if os.path.isdir(yara_dir) else []
            if yara_files:
                yara_file = yara_files[0]
                panel.append_line(f"   YARA   : {yara_file}")
            else:
                panel.append_line(
                    "   ⚠  No YARA rules found. Add .yar files to:\n"
                    f"      {os.path.join(self.case_data['base_dir'], 'yara')}"
                )

        worker = VolatilityWorker(
            image_path, plugin_id,
            base_dir=self.case_data["base_dir"],
            yara_file=yara_file,
            parent=self,
        )
        worker.output_ready.connect(panel.append_line)
        worker.os_detected.connect(self._switch_ribbon)
        worker.finished.connect(
            lambda code, pid=plugin_id, p=panel, b=btn:
            self._on_plugin_done(code, pid, p, b)
        )
        worker.error.connect(
            lambda msg, p=panel, b=btn:
            self._on_plugin_error(msg, p, b)
        )
        self._workers[plugin_id] = worker
        worker.start()
        log.info("Plugin started: %s", plugin_id)
        self._show_status(f"Running {clean_name}…")

    def _on_plugin_done(self, exit_code: int, plugin_id: str,
                        panel: ResultPanel, btn: PluginButton):
        panel.set_running(False)
        if btn:
            btn.set_running(False)
        panel.append_line("─" * 80)
        panel.append_line(
            "✓  Analysis complete." if exit_code == 0
            else f"⚠  Exited with code {exit_code}."
        )
        if self.db:
            try:
                self.db.save_analysis(plugin_id, panel.raw_view.toPlainText())
            except Exception as e:
                log.warning("DB save failed: %s", e)
        w = self._workers.pop(plugin_id, None)
        if w:
            w.wait()
        log.info("Plugin done: %s (exit %d)", plugin_id, exit_code)
        self._show_status(f"{plugin_id.split('.')[-1]} finished (exit {exit_code}).")

    def _on_plugin_error(self, msg: str, panel: ResultPanel, btn: PluginButton):
        log.error("Plugin error: %s", msg)
        panel.set_running(False)
        panel.set_error(msg)
        if btn:
            btn.set_running(False)

    def _close_tab(self, idx: int):
        if idx == 0:
            return
        self.tab_widget.removeTab(idx)

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def closeEvent(self, event):
        for worker in list(self._workers.values()):
            worker.stop()
            worker.quit()
            worker.wait(3000)
        self._workers.clear()
        super().closeEvent(event)

    # ── Theme ─────────────────────────────────────────────────────────────────

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

    def apply_theme(self):
        QApplication.instance().setStyleSheet(
            DARK_THEME if self.is_dark else LIGHT_THEME
        )
        self.theme_btn.setText("☀  Light" if self.is_dark else "🌙  Dark")
        border = "#30363d" if self.is_dark else "#d0d7de"
        tb_bg  = "#161b22" if self.is_dark else "#f6f8fa"
        rb_bg  = "#0d1117" if self.is_dark else "#f6f8fa"
        rt_bg  = "#161b22" if self.is_dark else "#f6f8fa"
        self.setStyleSheet(f"""
            QWidget#topBar        {{ background-color: {tb_bg}; border-bottom: 1px solid {border}; }}
            QWidget#pluginRibbon  {{ background-color: {rb_bg}; border-bottom: 1px solid {border}; }}
            QWidget#resultToolbar {{ background-color: {rt_bg}; border-bottom: 1px solid {border}; }}
        """)

    def _show_status(self, msg: str):
        self.status_bar.showMessage(f"  {msg}", 10000)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _lbl(text, style=""):
    l = QLabel(text)
    if style:
        l.setStyleSheet(style)
    return l


def _stat_card(title, value, icon):
    c = QWidget()
    c.setObjectName("statCard")
    c.setStyleSheet(
        "QWidget#statCard { background-color: #161b22; border: 1px solid #30363d;"
        "border-radius: 8px; padding: 14px 10px; }"
    )
    cl = QVBoxLayout(c)
    cl.setSpacing(4)
    cl.addWidget(_lbl(icon,  "font-size:22px;background:transparent;"))
    cl.addWidget(_lbl(value, "font-size:16px;font-weight:700;background:transparent;color:#e6edf3;"))
    cl.addWidget(_lbl(title, "font-size:10px;color:#8b949e;background:transparent;"))
    return c


def _file_size(path):
    try:
        b = os.path.getsize(path)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
    except Exception:
        return "—"
